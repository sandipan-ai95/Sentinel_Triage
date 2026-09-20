from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json()['status'] == 'ok'


def test_create_alert_ok():
    payload = {
        'timestamp': '2026-09-21T10:00:00Z',
        'source': 'auth',
        'rule_name': 'suspicious_login_pattern',
        'raw_summary': 'User login from unusual location.',
        'severity': 'high',
        'host': 'vpn-gateway-1',
        'user': 'analyst.one',
        'source_ip': '198.51.100.12',
        'destination_ip': '10.0.0.15',
        'asset_criticality': 'high',
        'event_count_10m': 3,
        'related_alert_count_24h': 1,
        'status': 'new',
    }

    response = client.post('/api/alerts', json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body['status'] in {'accepted', 'deduplicated'}

    listed = client.get('/api/alerts?limit=10')
    assert listed.status_code == 200
    assert any(item['id'] == body['id'] for item in listed.json())

    decision = client.post(
        f"/api/alerts/{body['id']}/decisions",
        json={"actor": "test-analyst", "decision": "approve_recommendation"},
    )
    assert decision.status_code == 200
    assert decision.json()['reward'] in {-1.0, 1.0}

    metrics = client.get('/api/metrics')
    assert metrics.status_code == 200
    assert metrics.json()['training_examples'] >= 1
