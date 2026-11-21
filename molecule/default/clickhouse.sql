-- Insert a fake trace after importing the packaged Zabbix telemetry schema.
INSERT INTO zabbixapm.otel_traces
    (Timestamp, TraceId, SpanId, SpanName, SpanKind, ServiceName, Duration, StatusCode)
SELECT now64(9), '0123456789abcdef0123456789abcdef', '0123456789abcdef',
       'Molecule APM test', 'Server', 'molecule-apm', 1000000, 'Ok'
WHERE NOT EXISTS
    (SELECT 1 FROM zabbixapm.otel_traces WHERE TraceId = '0123456789abcdef0123456789abcdef');
