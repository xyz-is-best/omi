import hashlib
import os
from unittest.mock import MagicMock, patch
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

os.environ.setdefault('ADMIN_KEY', 'test-admin-secret-key-123')

from routers import feedback_admin as router_module
from models.feedback import (
    FeedbackReport,
    FeedbackEvent,
    FeedbackReportEntry,
    FeedbackContextPointer,
    FeedbackContextHydrated,
    FeedbackSurface,
    FeedbackTargetKind,
)
from datetime import datetime, timezone


def _app():
    app = FastAPI()
    app.include_router(router_module.router)
    return app


@pytest.fixture
def client():
    return TestClient(_app())


def test_list_feedback_reports_firestore_failure_returns_500(client, monkeypatch):
    monkeypatch.setattr(
        router_module.feedback_db,
        'list_report_dates',
        lambda *args: (_ for _ in ()).throw(RuntimeError('Firestore timeout')),
    )
    headers = {'X-Admin-Key': 'test-admin-secret-key-123'}
    res = client.get('/v1/admin/feedback/reports', headers=headers)
    assert res.status_code == 500
    assert res.json()['detail'] == 'Failed to retrieve feedback report dates'


def test_get_feedback_report_firestore_failure_returns_500(client, monkeypatch):
    monkeypatch.setattr(
        router_module.feedback_db,
        'get_report',
        lambda *args: (_ for _ in ()).throw(RuntimeError('Firestore transport failure')),
    )
    headers = {'X-Admin-Key': 'test-admin-secret-key-123'}
    res = client.get('/v1/admin/feedback/reports/2026-09-01', headers=headers)
    assert res.status_code == 500
    assert res.json()['detail'] == 'Failed to retrieve feedback report'


def test_generate_feedback_report_failure_returns_500(client, monkeypatch):
    monkeypatch.setattr(
        router_module,
        'run_daily_report',
        lambda *args: (_ for _ in ()).throw(RuntimeError('Ledger query failure')),
    )
    headers = {'X-Admin-Key': 'test-admin-secret-key-123'}
    res = client.post('/v1/admin/feedback/reports/2026-09-01/generate', headers=headers)
    assert res.status_code == 500
    assert res.json()['detail'] == 'Failed to generate feedback report'


def test_generate_yesterdays_feedback_report_failure_returns_500(client, monkeypatch):
    monkeypatch.setattr(
        router_module,
        'run_daily_report',
        lambda *args: (_ for _ in ()).throw(RuntimeError('Ledger query failure')),
    )
    headers = {'X-Admin-Key': 'test-admin-secret-key-123'}
    res = client.post('/v1/admin/feedback/reports/generate-yesterday', headers=headers)
    assert res.status_code == 500
    assert res.json()['detail'] == 'Failed to generate nightly feedback report'


def test_get_feedback_event_context_invalid_id_format(client):
    headers = {'X-Admin-Key': 'test-admin-secret-key-123'}
    res = client.get('/v1/admin/feedback/events/   /context', headers=headers)
    assert res.status_code == 400
    assert res.json()['detail'] == 'Invalid event ID format'


def test_get_feedback_event_context_db_failure_returns_500(client, monkeypatch):
    monkeypatch.setattr(
        router_module.feedback_db,
        'get_feedback_event',
        lambda *args: (_ for _ in ()).throw(RuntimeError('Firestore read error')),
    )
    headers = {'X-Admin-Key': 'test-admin-secret-key-123'}
    res = client.get('/v1/admin/feedback/events/event-123/context', headers=headers)
    assert res.status_code == 500
    assert res.json()['detail'] == 'Failed to load feedback event'
