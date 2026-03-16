"""Tests for Job serialization, state management, and pickle round-trips."""

import pickle
from unittest.mock import patch


from tests.conftest import make_job


class TestGetState:
    """__getstate__ removes unpicklable attributes."""

    def test_removes_client(self):
        j = make_job()
        j.initialize_client()
        state = j.__getstate__()
        assert "client" not in state
        assert "async_client" not in state
        assert "_semaphore" not in state

    def test_preserves_other_attrs(self):
        j = make_job()
        j.initialize_client()
        state = j.__getstate__()
        assert state["name"] == "test"
        assert state["blocksize"] == 16
        assert state["mode"] == "decrypt"


class TestSetState:
    """__setstate__ restores state with backward compat."""

    def test_basic_restore(self):
        j = make_job()
        state = j.__dict__.copy()
        j2 = make_job()
        j2.__setstate__(state)
        assert j2.name == "test"
        assert j2.blocksize == 16

    def test_backward_compat_missing_fields(self):
        """Older pickles may not have byte-level progress fields."""
        j = make_job()
        state = j.__dict__.copy()
        # Remove the newer fields
        del state["block_solved_intermediates"]
        del state["block_solved_values"]
        del state["block_currentbyte"]
        del state["block_padding_num"]

        j2 = make_job()
        j2.__setstate__(state)
        assert j2.block_solved_intermediates == {}
        assert j2.block_solved_values == {}
        assert j2.block_currentbyte is None
        assert j2.block_padding_num is None


class TestClearByteProgress:
    def test_clears_all_fields(self):
        j = make_job()
        j.block_solved_intermediates = {15: 0x42}
        j.block_solved_values = {15: 0x55}
        j.block_currentbyte = 14
        j.block_padding_num = 2

        j._clear_byte_progress()

        assert j.block_solved_intermediates == {}
        assert j.block_solved_values == {}
        assert j.block_currentbyte is None
        assert j.block_padding_num is None


class TestSaveByteProgress:
    def test_saves_copies(self):
        j = make_job()
        j.initialize_client()
        intermediates = {15: 0x42}
        values = {15: 0x55}

        with patch("blockbuster.blockbuster.saveState"):
            j._save_byte_progress(intermediates, values, 14, 2)

        assert j.block_solved_intermediates == {15: 0x42}
        assert j.block_solved_values == {15: 0x55}
        assert j.block_currentbyte == 14
        assert j.block_padding_num == 2

        # Verify it's a copy, not a reference
        intermediates[15] = 0xFF
        assert j.block_solved_intermediates[15] == 0x42

    def test_calls_saveState(self):
        j = make_job()
        j.initialize_client()

        with patch("blockbuster.blockbuster.saveState") as mock_save:
            j._save_byte_progress({}, {}, 15, 1)
        mock_save.assert_called_once_with(j)


class TestPickleRoundTrip:
    """Full pickle serialize/deserialize cycle."""

    def test_basic_round_trip(self):
        j = make_job()
        j.initialize_client()
        j.solvedBlocks = {0: b"block0", 1: b"block1"}
        j.block_solved_intermediates = {15: 0x42, 14: 0x33}
        j.currentBlock = 1

        data = pickle.dumps(j)
        j2 = pickle.loads(data)

        assert j2.name == "test"
        assert j2.solvedBlocks == {0: b"block0", 1: b"block1"}
        assert j2.block_solved_intermediates == {15: 0x42, 14: 0x33}
        assert j2.currentBlock == 1

    def test_client_absent_after_unpickle(self):
        j = make_job()
        j.initialize_client()

        data = pickle.dumps(j)
        j2 = pickle.loads(data)

        assert not hasattr(j2, "client") or j2.__dict__.get("client") is None
        assert (
            not hasattr(j2, "async_client") or j2.__dict__.get("async_client") is None
        )

    def test_initialize_client_after_unpickle(self):
        j = make_job()
        j.initialize_client()

        data = pickle.dumps(j)
        j2 = pickle.loads(data)
        j2.initialize_client()

        assert hasattr(j2, "client")
        assert j2.client is not None

    def test_backward_compat_pickle(self):
        """Simulate loading an older pickle without byte-level fields."""
        j = make_job()
        j.initialize_client()

        # Manually remove byte-level fields before pickling
        state = j.__getstate__()
        del state["block_solved_intermediates"]
        del state["block_solved_values"]
        del state["block_currentbyte"]
        del state["block_padding_num"]

        j2 = make_job()
        j2.__setstate__(state)

        assert j2.block_solved_intermediates == {}
        assert j2.block_solved_values == {}
        assert j2.block_currentbyte is None
        assert j2.block_padding_num is None

    def test_backward_compat_via_real_pickle(self):
        """Pickle a job, strip the new fields from raw bytes, unpickle."""
        j = make_job()
        data = pickle.dumps(j)
        j2 = pickle.loads(data)
        # Now manually delete the fields and re-run __setstate__
        del j2.__dict__["block_solved_intermediates"]
        del j2.__dict__["block_solved_values"]
        del j2.__dict__["block_currentbyte"]
        del j2.__dict__["block_padding_num"]
        # Re-trigger __setstate__ which the pickle normally calls
        j2.__setstate__(j2.__dict__)
        assert j2.block_solved_intermediates == {}
        assert j2.block_currentbyte is None


class TestInitializeClient:
    def test_creates_clients(self):
        j = make_job()
        j.initialize_client()
        assert j.client is not None
        assert j.async_client is not None

    def test_proxy_config(self):
        j = make_job(httpProxyOn=True, httpProxyIp="127.0.0.1", httpProxyPort=8080)
        j.initialize_client()
        # Just verify it doesn't crash
        assert j.client is not None

    def test_semaphore_property(self):
        j = make_job(concurrency=10)
        j.initialize_client()
        sem = j.semaphore
        assert sem is not None
        # Second access returns same object
        assert j.semaphore is sem
