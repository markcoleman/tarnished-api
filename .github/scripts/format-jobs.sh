#!/bin/bash
set -e

INPUT_FILE="$1"
LATEST_RUN_ID="$2"
REPO="$3"
WORKFLOW_NAME="$4"

rm -f formatted_jobs.json

jq -c '[.jobs[] | select(.steps != null) | { 
  repository: "'$REPO'",
  workflow_name: "'$WORKFLOW_NAME'",
  run_id: "'$LATEST_RUN_ID'",
  job_id: .id,
  job_name: .name,
  job_status: .status,
  job_conclusion: .conclusion,
  job_started_at: .started_at,
  job_completed_at: .completed_at,
  steps: .steps
} as $job | $job.steps[] | {
  repository: $job.repository,
  workflow_name: $job.workflow_name,
  run_id: $job.run_id,
  job_id: $job.job_id,
  job_name: $job.job_name,
  job_status: $job.job_status,
  job_conclusion: $job.job_conclusion,
  job_started_at: $job.job_started_at,
  job_completed_at: $job.job_completed_at,
  step_name: .name,
  step_status: .status,
  step_conclusion: .conclusion,
  step_started_at: .started_at,
  step_completed_at: .completed_at
}]' "$INPUT_FILE" > formatted_jobs.json