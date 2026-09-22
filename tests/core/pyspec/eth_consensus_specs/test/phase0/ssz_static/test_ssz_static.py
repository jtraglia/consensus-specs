import hashlib
from inspect import getmembers, isclass
from random import Random

from ssz.bitfields import ProgressiveBitList
from ssz.collections import ProgressiveList
from ssz.container import Container, ProgressiveContainer

from eth_consensus_specs.debug import encode, random_value
from eth_consensus_specs.test.context import (
    only_generator,
    single_phase,
    spec_targets,
    spec_test,
    with_phases,
    with_presets,
)
from eth_consensus_specs.test.helpers.constants import MAINNET, MINIMAL, TESTGEN_FORKS
from eth_consensus_specs.test.utils.manifest import Manifest, manifest
from eth_consensus_specs.test.utils.template_test import template_test
from eth_consensus_specs.utils.ssz.ssz_impl import serialize

MAX_BYTES_LENGTH = 1000
MAX_LIST_LENGTH = 10
# Limit cases encode a list at and just past its declared limit, skip types whose
# encoding at the limit would be unreasonably large to ship as a test vector.
MAX_LIMIT_CASE_BYTES = 16 * 1024 * 1024


@template_test
def _template_ssz_static_tests(
    unique_name: str,
    _manifest: Manifest,
    ssz_type_name,
    phases: list[str],
    mode: random_value.RandomizationMode,
    chaos: bool,
    count: int,
    i: int,
):
    def _deterministic_seed(**kwargs) -> int:
        """Need this since hash() is not deterministic between runs."""
        m = hashlib.sha256()
        for k, v in sorted(kwargs.items()):
            m.update(f"{k}={v}".encode())
        return int.from_bytes(m.digest()[:8], "little")

    @manifest(_manifest)
    @with_phases(phases)
    @with_presets([_manifest.preset_name])
    @spec_test
    @single_phase
    def the_test(spec):
        ssz_type = getattr(spec, ssz_type_name)

        random_mode_name = mode.to_name()
        seed = _deterministic_seed(
            fork_name=_manifest.fork_name,
            preset_name=_manifest.preset_name,
            name=_manifest.handler_name,
            ssz_type_name=ssz_type.__name__,
            random_mode_name=random_mode_name,
            chaos=chaos,
            count=count,
            i=i,
        )

        rng = Random(seed)
        value = random_value.get_random_ssz_object(
            rng,
            ssz_type,
            MAX_BYTES_LENGTH,
            MAX_LIST_LENGTH,
            mode,
            chaos,
        )
        yield "value", "data", encode.encode(value)
        yield "serialized", "ssz", serialize(value)
        roots_data = {"root": "0x" + spec.hash_tree_root(value).hex()}
        yield "roots", "data", roots_data

    return (the_test, f"test_{unique_name}")


def _is_bounded_list(ssz_type) -> bool:
    return (
        isclass(ssz_type)
        and issubclass(ssz_type, ProgressiveList | ProgressiveBitList)
        and ssz_type not in (ProgressiveList, ProgressiveBitList)
        and ssz_type.LIMIT is not None
    )


def _unbounded_twin(ssz_type):
    """
    The same shape without the declared limit, to encode a value the bounded type refuses.
    Serialization and merkleization do not depend on the limit, only validation does.
    """
    if issubclass(ssz_type, ProgressiveBitList):
        return type(f"{ssz_type.__name__}Unbounded", (ProgressiveBitList,), {})
    return type(f"{ssz_type.__name__}Unbounded", (ProgressiveList[ssz_type.ELEMENT_TYPE],), {})


def _container_with_unbounded_field(container_type, field_name: str):
    """The same container with one list field replaced by its unbounded twin."""
    fields = {name: field.annotation for name, field in container_type.model_fields.items()}
    fields[field_name] = _unbounded_twin(fields[field_name])
    namespace = {"__annotations__": fields}
    if issubclass(container_type, ProgressiveContainer):
        namespace["ACTIVE_FIELDS"] = container_type.ACTIVE_FIELDS
        return type(f"{container_type.__name__}Unbounded", (ProgressiveContainer,), namespace)
    return type(f"{container_type.__name__}Unbounded", (Container,), namespace)


def _elements(ssz_type, count: int) -> list:
    if issubclass(ssz_type, ProgressiveBitList):
        return [False] * count
    return [ssz_type.ELEMENT_TYPE()] * count


def _list_type(ssz_type, field_name: str | None):
    """The bounded list itself, or the one a container holds in the named field."""
    return ssz_type if field_name is None else ssz_type.model_fields[field_name].annotation


def _filled(ssz_type, field_name: str | None, count: int, bounded: bool):
    """
    The type with `count` default elements in the list, or in the named container field.
    The unbounded twin encodes what the declared limit refuses.
    """
    if field_name is None:
        list_type = ssz_type if bounded else _unbounded_twin(ssz_type)
        return list_type(data=_elements(list_type, count))
    container_type = ssz_type if bounded else _container_with_unbounded_field(ssz_type, field_name)
    list_type = _list_type(container_type, field_name)
    return container_type(**{field_name: list_type(data=_elements(list_type, count))})


def _limit_case_bytes(ssz_type) -> int:
    """Encoded size of the type filled to one past its limit, using default elements."""
    twin = _unbounded_twin(ssz_type)
    unit = len(serialize(twin(data=_elements(ssz_type, 2)))) - len(
        serialize(twin(data=_elements(ssz_type, 1)))
    )
    return (ssz_type.LIMIT + 1) * max(unit, 1)


@template_test
def _template_ssz_limit_tests(
    unique_name: str,
    _manifest: Manifest,
    ssz_type_name,
    field_name: str | None,
    phases: list[str],
    over_limit: bool,
):
    @manifest(_manifest)
    @with_phases(phases)
    @with_presets([_manifest.preset_name])
    @spec_test
    @single_phase
    def the_test(spec):
        ssz_type = getattr(spec, ssz_type_name)
        limit = _list_type(ssz_type, field_name).LIMIT

        # Each case declares its own validity, runners branch on it rather than on the case name
        yield "valid", "meta", not over_limit
        if over_limit:
            # One element past the limit, encoded through the unbounded twin since the bounded
            # type refuses to hold it. Only the bytes are emitted, decoding them must fail.
            value = _filled(ssz_type, field_name, limit + 1, bounded=False)
            yield "serialized", "ssz", serialize(value)
        else:
            value = _filled(ssz_type, field_name, limit, bounded=True)
            yield "value", "data", encode.encode(value)
            yield "serialized", "ssz", serialize(value)
            roots_data = {"root": "0x" + spec.hash_tree_root(value).hex()}
            yield "roots", "data", roots_data

    return (the_test, f"test_{unique_name}")


@only_generator("too slow")
def _create_test_cases():
    """
    Create test cases for all SSZ types in all forks and both presets.
    Uses _template_ssz_tests to create the actual tests.
    """

    def _create_test_case(
        phases: list[str],
        preset_name: str,
        ssz_type_name: str,
        mode: random_value.RandomizationMode,
        chaos: bool,
        count: int,
    ):
        random_mode_name = mode.to_name()
        for i in range(count):
            manifest = Manifest(
                preset_name=preset_name,
                runner_name="ssz_static",
                handler_name=ssz_type_name,
                suite_name=f"ssz_{random_mode_name}{'_chaos' if chaos else ''}",
                case_name=f"case_{i}",
            )

            unique_name = f"ssz_{random_mode_name}{'_chaos' if chaos else ''}_{preset_name}_{ssz_type_name}_case_{i}"

            _template_ssz_static_tests(
                unique_name, manifest, ssz_type_name, phases, mode, chaos, count, i
            )

    def _get_spec_ssz_types_names(spec: str) -> list[str]:
        return [
            name
            for (name, value) in getmembers(spec, isclass)
            if issubclass(value, Container | ProgressiveContainer)
            # only the subclasses, not the imported base class
            and value != Container
            and value != ProgressiveContainer
        ]

    def _get_spec_bounded_lists(spec: str) -> list[tuple[str, str | None]]:
        """
        Bounded progressive lists as (type name, None), and every container field holding one as
        (container name, field name). Lists too large to encode at their limit are excluded.
        """
        container_names = set(_get_spec_ssz_types_names(spec))
        bounded = []
        for name, value in getmembers(spec, isclass):
            if _is_bounded_list(value) and _limit_case_bytes(value) <= MAX_LIMIT_CASE_BYTES:
                bounded.append((name, None))
            elif name in container_names:
                for field_name, field in value.model_fields.items():
                    if (
                        _is_bounded_list(field.annotation)
                        and _limit_case_bytes(field.annotation) <= MAX_LIMIT_CASE_BYTES
                    ):
                        bounded.append((name, field_name))
        return bounded

    def _get_ssz_types_to_specs_mapping() -> dict[str, list[str]]:
        """
        Returns a dictionary where key is a SSZ type name and the value is a list of specs that have it.
        """
        ssz_type_to_specs = {}

        # Check all forks using MINIMAL preset
        for fork in TESTGEN_FORKS:
            spec = spec_targets[MINIMAL][fork]

            # Get all SSZ types for this spec
            ssz_type_names = _get_spec_ssz_types_names(spec)

            # Add each type to the mapping
            for ssz_type_name in ssz_type_names:
                if ssz_type_name not in ssz_type_to_specs:
                    ssz_type_to_specs[ssz_type_name] = []
                ssz_type_to_specs[ssz_type_name].append(fork)

        return ssz_type_to_specs

    settings = []
    for mode in random_value.RandomizationMode:
        settings.append((MINIMAL, mode, False, 30))
    settings.append((MINIMAL, random_value.RandomizationMode.mode_random, True, 30))
    settings.append((MAINNET, random_value.RandomizationMode.mode_random, False, 5))

    ssz_type_to_specs = _get_ssz_types_to_specs_mapping()

    for preset, mode, chaos, cases_if_random in settings:
        count = cases_if_random if chaos or mode.is_changing() else 1
        for ssz_type_name in ssz_type_to_specs:
            _create_test_case(
                ssz_type_to_specs[ssz_type_name], preset, ssz_type_name, mode, chaos, count
            )

    # Limit cases: every bounded progressive list at its limit and one past it, standalone and in
    # each container field holding it. Per preset since the limits differ between presets.
    for preset in (MINIMAL, MAINNET):
        bounded_to_specs: dict[tuple[str, str | None], list[str]] = {}
        for fork in TESTGEN_FORKS:
            for bounded in _get_spec_bounded_lists(spec_targets[preset][fork]):
                bounded_to_specs.setdefault(bounded, []).append(fork)
        for (ssz_type_name, field_name), phases in bounded_to_specs.items():
            for suffix, over_limit in (("at_limit", False), ("over_limit", True)):
                case_name = suffix if field_name is None else f"{field_name}_{suffix}"
                manifest = Manifest(
                    preset_name=preset,
                    runner_name="ssz_static",
                    handler_name=ssz_type_name,
                    suite_name="ssz_limit",
                    case_name=case_name,
                )
                _template_ssz_limit_tests(
                    f"ssz_limit_{preset}_{ssz_type_name}_{case_name}",
                    manifest,
                    ssz_type_name,
                    field_name,
                    phases,
                    over_limit,
                )


_create_test_cases()
