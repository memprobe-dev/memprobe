"""Django models for the memprobe webapp."""

from django.db import models


class AnalysisJob(models.Model):
    """Tracks the status of a background ELF/map analysis job."""

    STATUS_PENDING   = 'pending'
    STATUS_RUNNING   = 'running'
    STATUS_DONE      = 'done'
    STATUS_FAILED    = 'failed'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_RUNNING, 'Running'),
        (STATUS_DONE,    'Done'),
        (STATUS_FAILED,  'Failed'),
    ]

    # Short random ID surfaced to the client (not the DB PK).
    job_id   = models.CharField(max_length=32, unique=True, db_index=True)
    status   = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_PENDING)
    # Real progress fraction 0.0-1.0 reported by the Modal worker.
    progress = models.FloatField(default=0.0)

    # Who owns this job (null for guest sessions).
    user_id  = models.CharField(max_length=128, blank=True, null=True, db_index=True)

    # Original filename shown in progress UI.
    filename = models.CharField(max_length=255, blank=True)

    # Stored as JSON once analysis completes successfully.
    result_json = models.TextField(blank=True)

    # Human-readable error shown on failure.
    error_message = models.CharField(max_length=512, blank=True)

    created_at  = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'AnalysisJob({self.job_id}, {self.status})'
