-- Integration test seed data
-- Minimum data the API requires to function

INSERT INTO policy_packs (
    policy_pack_id, org_id, name, version, checks, created_at,
    signer_id, kid, signature
) VALUES (
    'default',
    'testorg',
    'Integration Test Pack',
    '1.0.0',
    '[]',
    NOW(),
    'test_signer',
    'test_kid',
    '{"algorithm":"test","signature":"test"}'
);

INSERT INTO observation_surfaces (
    surface_id, org_id, environment, surface_type, surface_name,
    surface_version, observation_mode, scope_type, scope_description,
    surface_coverage_statement, proof_ceiling, registered_at
) VALUES (
    'default',
    'testorg',
    'test',
    'sdk',
    'Integration Test Surface',
    '1.0.0',
    'inline',
    'process',
    'Integration test scope',
    'Full coverage for integration testing',
    'attestation',
    NOW()
);
