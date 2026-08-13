"""Test-only execution/proof engine stubs."""


class NoopExecutionEngine:
    def notify_new_payload(self, *args, **kwargs):
        return True

    def is_valid_block_hash(self, *args, **kwargs):
        return True

    def is_valid_versioned_hashes(self, *args, **kwargs):
        return True

    def notify_forkchoice_updated(self, *args, **kwargs):
        return None

    def get_payload(self, *args, **kwargs):
        raise NotImplementedError("no default block production")

    def verify_and_notify_new_payload(self, *args, **kwargs):
        return True

    def get_inclusion_list(self, *args, **kwargs):
        raise NotImplementedError("no default inclusion list production")

    def is_inclusion_list_satisfied(self, *args, **kwargs):
        return True


class NoopProofEngine:
    def verify_execution_proof(self, *args, **kwargs):
        return True

    def notify_new_payload(self, *args, **kwargs):
        return None

    def notify_forkchoice_updated(self, *args, **kwargs):
        return None

    def request_proofs(self, *args, **kwargs):
        raise NotImplementedError("no default proof generation")


def install_noop_engines(spec) -> None:
    spec.NoopExecutionEngine = NoopExecutionEngine
    spec.EXECUTION_ENGINE = NoopExecutionEngine()
    spec.NoopProofEngine = NoopProofEngine
    spec.PROOF_ENGINE = NoopProofEngine()
