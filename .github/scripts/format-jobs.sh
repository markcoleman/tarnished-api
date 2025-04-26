#!/bin/bash
set -e

INPUT_FILE="$1"
LATEST_RUN_ID="$2"
REPO="$3"
WORKFLOW_NAME="$4"

jq -c '.jobs[] | {
  repository: "'$REPO'",
  workflow_name: "'$WORKFLOW_NAME'",
  run_id: "'$LATEST_RUN_ID'",
  job_id: .id,
  job_name: .name,
  job_status: .status,
  job_conclusion: .conclusion,
  job_started_at: .started_at,
  job_completed_at: .completed_at,
  steps: [
    .steps[] | {
      step_name: .name,
      step_status: .status,
      step_conclusion: .conclusion,
      step_started_at: .started_at,
      step_completed_at: .completed_at
    }
  ]
}' "$INPUT_FILE" > formatted_jobs.json