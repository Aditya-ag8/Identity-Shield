"""Rule model, reference Sigma-subset parser, and evaluator.

Design note
-----------
Sigma rules are parsed twice in this project:

* ``pysigma_backend`` converts them using pySigma's object model. That is the
  deliverable, and its success rate is the compile-rate gate.
* this module implements the same subset directly from YAML, as a **reference**.
  When the two disagree on a fixture, one of them has a bug, and a test asserts
  they agree.

Evaluation is a Python scan over parsed event dicts rather than SQL. At the
expected volume (tens of thousands of events) that is not a bottleneck, and it
avoids SQLite JSON-path and REGEXP portability problems.

Supported Sigma subset (v1)
---------------------------
* field selections as ``field: value``, ``field: [v1, v2]``, and lists of
  mappings (OR of ANDs)
* modifiers: ``contains``, ``startswith``, ``endswith``, ``re``, ``all``
* conditions: ``and`` / ``or`` / ``not`` / parentheses,
  ``1 of them``, ``all of them``, ``<n> of <pattern>``, ``all of <pattern>``
* ``*`` and ``?`` wildcards inside plain string values
* field paths may be dotted (``userIdentity.type``) and are resolved
  case-insensitively, because CloudTrail field casing varies between rules

Operators
---------
``eq``       case-insensitive equality, wildcards allowed
``contains`` substring, wildcards allowed
``startswith`` / ``endswith``
``re``      unanchored regex search (Sigma's ``|re`` modifier)
``regex``   fullmatch over a pattern that already encodes its own wildcards
            (what the pySigma backend emits)
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

import yaml

VALUE_MODIFIERS = {"contains", "startswith", "endswith", "re"}
KNOWN_MODIFIERS = VALUE_MODIFIERS | {"all"}


class RuleError(Exception):
    """Base class for rule problems."""


class UnsupportedRule(RuleError):
    """The rule uses Sigma features outside the supported subset."""


@dataclass(frozen=True, slots=True)
class FieldMatch:
    path: str
    op: str = "eq"
    values: tuple[str, ...] = ()
    match_all: bool = False


@dataclass(frozen=True, slots=True)
class BoolNode:
    op: str
    children: tuple["Node", ...] = ()
    count: int = 0


Node = FieldMatch | BoolNode


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def get_field(event: Mapping[str, Any], path: str) -> Any:
    current: Any = event
    for part in path.split("."):
        if not isinstance(current, Mapping):
            return None
        if part in current:
            current = current[part]
            continue
        lowered = part.lower()
        found = next(
            (key for key in current if isinstance(key, str) and key.lower() == lowered),
            None,
        )
        if found is None:
            return None
        current = current[found]
    return current


def as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


def _wildcard_pattern(pattern: str, anchored: bool) -> re.Pattern[str]:
    pieces: list[str] = []
    for char in pattern:
        if char == "*":
            pieces.append(".*")
        elif char == "?":
            pieces.append(".")
        else:
            pieces.append(re.escape(char))
    body = "".join(pieces)
    return re.compile(f"^{body}$" if anchored else body, re.IGNORECASE | re.DOTALL)


def _has_wildcard(value: str) -> bool:
    return "*" in value or "?" in value


def match_value(actual: Any, value: str, op: str) -> bool:
    if isinstance(actual, (list, tuple, set)):
        return any(match_value(item, value, op) for item in actual)

    text = as_text(actual)
    if actual is None:
        return False

    if op == "re":
        try:
            return re.search(value, text, re.IGNORECASE) is not None
        except re.error as exc:  # a broken regex must not take the run down
            raise UnsupportedRule(f"invalid regex {value!r}: {exc}") from exc

    if op == "regex":
        # Patterns produced by the pySigma backend carry their own wildcards
        # (``contains`` becomes ``.*x.*``), so fullmatch gives the right
        # semantics for every modifier without per-modifier special cases.
        try:
            return re.fullmatch(value, text, re.IGNORECASE | re.DOTALL) is not None
        except re.error as exc:
            raise UnsupportedRule(f"invalid regex {value!r}: {exc}") from exc

    if op == "eq":
        if _has_wildcard(value):
            return _wildcard_pattern(value, anchored=True).match(text) is not None
        return text.casefold() == value.casefold()

    if op == "contains":
        if _has_wildcard(value):
            return _wildcard_pattern(value, anchored=False).search(text) is not None
        return value.casefold() in text.casefold()

    if op == "startswith":
        return text.casefold().startswith(value.casefold())

    if op == "endswith":
        return text.casefold().endswith(value.casefold())

    raise UnsupportedRule(f"unsupported operator {op!r}")


def evaluate(node: Node, event: Mapping[str, Any]) -> bool:
    if isinstance(node, FieldMatch):
        if not node.values:
            return False
        actual = get_field(event, node.path)
        results = (match_value(actual, value, node.op) for value in node.values)
        return all(results) if node.match_all else any(results)

    if node.op == "and":
        return all(evaluate(child, event) for child in node.children)
    if node.op == "or":
        return any(evaluate(child, event) for child in node.children)
    if node.op == "not":
        return not evaluate(node.children[0], event)
    if node.op == "at_least":
        hits = sum(1 for child in node.children if evaluate(child, event))
        return hits >= node.count

    raise UnsupportedRule(f"unknown node operator {node.op!r}")


# ---------------------------------------------------------------------------
# Reference Sigma parsing
# ---------------------------------------------------------------------------


def parse_detection(detection: Mapping[str, Any]) -> Node:
    if not isinstance(detection, Mapping):
        raise UnsupportedRule("detection must be a mapping")

    condition = detection.get("condition")
    if condition is None:
        raise UnsupportedRule("detection has no condition")

    selections: dict[str, Node] = {}
    for key, value in detection.items():
        if key in ("condition", "timeframe"):
            continue
        selections[str(key)] = parse_selection(value)

    if not selections:
        raise UnsupportedRule("detection has no selections")

    return parse_condition(condition, selections)


def parse_selection(value: Any) -> Node:
    if isinstance(value, list):
        if not value:
            raise UnsupportedRule("empty selection list")
        nodes = [parse_selection(item) for item in value]
        return _combine("or", nodes)
    if isinstance(value, Mapping):
        nodes = [parse_field(str(key), item) for key, item in value.items()]
        return _combine("and", nodes)
    raise UnsupportedRule("selection must be a mapping or a list of mappings")


def parse_field(key: str, value: Any) -> FieldMatch:
    parts = [part.strip() for part in key.split("|")]
    path = parts[0]
    if not path:
        raise UnsupportedRule("empty field name")

    op = "eq"
    match_all = False
    for modifier in (part.lower() for part in parts[1:] if part):
        if modifier in VALUE_MODIFIERS:
            if op != "eq":
                raise UnsupportedRule(f"conflicting value modifiers in {key!r}")
            op = modifier
        elif modifier == "all":
            match_all = True
        else:
            raise UnsupportedRule(f"unsupported modifier {modifier!r} in {key!r}")

    if isinstance(value, Mapping):
        raise UnsupportedRule(f"nested mapping value for {key!r}")

    if isinstance(value, list):
        values = tuple(as_text(item) for item in value)
    else:
        values = (as_text(value),)

    if not values:
        raise UnsupportedRule(f"empty value list for {key!r}")

    return FieldMatch(path=path, op=op, values=values, match_all=match_all)


def _combine(op: str, nodes: Sequence[Node]) -> Node:
    if len(nodes) == 1:
        return nodes[0]
    return BoolNode(op=op, children=tuple(nodes))


_TOKEN_RE = re.compile(r"\s*(\(|\)|[A-Za-z0-9_.\-*]+)")


def _tokenize(condition: str) -> list[str]:
    tokens: list[str] = []
    position = 0
    while position < len(condition):
        match = _TOKEN_RE.match(condition, position)
        if not match:
            if condition[position:].strip() == "":
                break
            raise UnsupportedRule(f"cannot tokenize condition at {condition[position:][:16]!r}")
        token = match.group(1)
        if token:
            tokens.append(token)
        position = match.end()
    return tokens


def parse_condition(condition: Any, selections: Mapping[str, Node]) -> Node:
    if isinstance(condition, (list, tuple)):
        return _combine("or", [parse_condition(item, selections) for item in condition])
    if not isinstance(condition, str):
        raise UnsupportedRule("condition must be a string")

    tokens = _tokenize(condition)
    if not tokens:
        raise UnsupportedRule("empty condition")

    parser = _ConditionParser(tokens, selections)
    node = parser.parse_or()
    if parser.position != len(tokens):
        raise UnsupportedRule(f"trailing tokens in condition: {tokens[parser.position:]!r}")
    return node


class _ConditionParser:
    def __init__(self, tokens: Sequence[str], selections: Mapping[str, Node]) -> None:
        self.tokens = list(tokens)
        self.selections = selections
        self.position = 0

    def peek(self) -> str | None:
        if self.position >= len(self.tokens):
            return None
        return self.tokens[self.position]

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise UnsupportedRule("unexpected end of condition")
        self.position += 1
        return token

    def parse_or(self) -> Node:
        node = self.parse_and()
        while (token := self.peek()) and token.lower() == "or":
            self.take()
            node = BoolNode("or", (node, self.parse_and()))
        return node

    def parse_and(self) -> Node:
        node = self.parse_factor()
        while (token := self.peek()) and token.lower() == "and":
            self.take()
            node = BoolNode("and", (node, self.parse_factor()))
        return node

    def parse_factor(self) -> Node:
        token = self.peek()
        if token is None:
            raise UnsupportedRule("unexpected end of condition")

        if token == "(":
            self.take()
            node = self.parse_or()
            if self.peek() != ")":
                raise UnsupportedRule("unbalanced parentheses in condition")
            self.take()
            return node

        if token.lower() == "not":
            self.take()
            return BoolNode("not", (self.parse_factor(),))

        if token.lower() == "all" or token.isdigit():
            lookahead = self.tokens[self.position + 1 : self.position + 2]
            if lookahead and lookahead[0].lower() == "of":
                return self.parse_quantifier()

        self.take()
        return self.resolve(token)

    def parse_quantifier(self) -> Node:
        counter = self.take()
        if (self.peek() or "").lower() != "of":
            raise UnsupportedRule("quantifier without 'of'")
        self.take()
        pattern = self.take()
        names = self.expand(pattern)
        nodes = [self.resolve(name) for name in names]

        if counter.lower() == "all":
            return BoolNode("and", tuple(nodes))
        if not counter.isdigit():
            raise UnsupportedRule(f"unsupported quantifier {counter!r}")
        count = int(counter)
        if count <= 0:
            raise UnsupportedRule("quantifier must be >= 1")
        return BoolNode("at_least", tuple(nodes), count=count)

    def expand(self, pattern: str) -> list[str]:
        lowered = pattern.lower()
        if lowered == "them":
            names = list(self.selections)
        elif "*" in pattern or "?" in pattern:
            names = [name for name in self.selections if fnmatch.fnmatchcase(name, pattern)]
        else:
            names = [pattern]
        if not names:
            raise UnsupportedRule(f"condition pattern {pattern!r} matches no selection")
        return names

    def resolve(self, name: str) -> Node:
        if name in self.selections:
            return self.selections[name]
        lowered = name.lower()
        for key, node in self.selections.items():
            if key.lower() == lowered:
                return node
        raise UnsupportedRule(f"condition references unknown selection {name!r}")


# ---------------------------------------------------------------------------
# Rule objects
# ---------------------------------------------------------------------------


@dataclass
class Rule:
    native_id: str
    title: str
    level: str = "medium"
    technique_id: str | None = None
    loader: str = "sigma"
    body: str = ""
    path: str | None = None
    node: Node | None = None
    fn: Callable[[Mapping[str, Any]], bool] | None = None
    description: str = ""
    fields: tuple[str, ...] = field(default_factory=tuple)
    cloud_provider: str | None = None
    logsource_service: str | None = None

    def matches_cloud(self, event_cloud: str | None) -> bool:
        """Return True if rule applies to the event's cloud provider."""
        if not self.cloud_provider or not event_cloud:
            return True
        if self.cloud_provider in {"generic", "all", "unknown"}:
            return True
        return self.cloud_provider.lower() == str(event_cloud).lower()

    def matches(self, event: Mapping[str, Any]) -> bool:
        if self.fn is not None:
            return bool(self.fn(event))
        if self.node is None:
            return False
        return evaluate(self.node, event)


_TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def technique_from_tags(tags: Any) -> str | None:
    if not isinstance(tags, (list, tuple)):
        return None
    for tag in tags:
        match = _TECHNIQUE_TAG_RE.match(str(tag).strip())
        if match:
            return match.group(1).upper()
    return None


def collect_fields(node: Node | None) -> tuple[str, ...]:
    if node is None:
        return ()
    if isinstance(node, FieldMatch):
        return (node.path,)
    names: list[str] = []
    for child in node.children:
        for name in collect_fields(child):
            if name not in names:
                names.append(name)
    return tuple(names)


def rule_from_document(document: Mapping[str, Any], *, path: str | None = None) -> Rule:
    """Build a Rule from a parsed Sigma YAML document using the reference parser."""
    detection = document.get("detection")
    if not isinstance(detection, Mapping):
        raise UnsupportedRule("missing detection block")

    node = parse_detection(detection)
    native_id = str(document.get("id") or (path or "unnamed"))
    body = yaml.safe_dump(document, sort_keys=False)
    logsource = document.get("logsource") if isinstance(document.get("logsource"), Mapping) else {}
    product = str(logsource.get("product") or "").strip().lower() or None
    if product not in {"aws", "gcp", "azure", "generic", None}:
        product = None
    svc = str(logsource.get("service") or "").strip().lower() or None

    return Rule(
        native_id=native_id,
        title=str(document.get("title") or native_id),
        level=str(document.get("level") or "medium"),
        technique_id=technique_from_tags(document.get("tags")),
        loader="sigma",
        body=body,
        path=path,
        node=node,
        description=str(document.get("description") or ""),
        fields=collect_fields(node),
        cloud_provider=product,
        logsource_service=svc,
    )


def load_sigma_text(text: str, *, path: str | None = None) -> Rule:
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise UnsupportedRule(f"invalid YAML: {exc}") from exc
    if not isinstance(document, Mapping):
        raise UnsupportedRule("rule document is not a mapping")
    return rule_from_document(document, path=path)


def load_sigma_file(path: str) -> Rule:
    with open(path, encoding="utf-8") as handle:
        return load_sigma_text(handle.read(), path=path)
