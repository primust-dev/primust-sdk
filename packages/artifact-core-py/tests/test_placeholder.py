def test_import():
    import primust_artifact_core
    assert primust_artifact_core is not None
    assert hasattr(primust_artifact_core, "canonical")
    assert hasattr(primust_artifact_core, "sign")
    assert hasattr(primust_artifact_core, "verify")
