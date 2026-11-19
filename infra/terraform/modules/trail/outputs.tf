output "bucket_name" {
  value = aws_s3_bucket.trail.id
}

output "bucket_arn" {
  value = local.bucket_arn
}

output "trail_name" {
  value = aws_cloudtrail.main.name
}

output "trail_arn" {
  value = aws_cloudtrail.main.arn
}

output "queue_url" {
  value = aws_sqs_queue.trail.id
}

output "queue_arn" {
  value = aws_sqs_queue.trail.arn
}
