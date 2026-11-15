#!/usr/bin/env python3
"""Fail closed unless a warm output base first admits the production docs rule after B."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import pathlib
import re
import tarfile


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


parser = argparse.ArgumentParser()
for name in ("action", "attack-rule", "control-log", "control-rule", "diagnostic-archive", "diagnostic-proto", "emitter", "fetched-proto", "output", "pre-admission", "protobuf", "readback", "site-tar"):
    parser.add_argument("--" + name, required=True, type=pathlib.Path)
parser.add_argument("--control-rc", required=True, type=int)
parser.add_argument("--registry-commit", required=True)
args = parser.parse_args()

emitter = json.loads(args.emitter.read_text())
if emitter.get("production_function") != "language/bcr.makeBinaryProtoRepository" or emitter.get("production_has_sha256") is not False:
    raise SystemExit("emitter does not bind the hashless production function")
expected = emitter["expected_sha256"]
attack_rule, control_rule = args.attack_rule.read_text(), args.control_rule.read_text()
if "sha256" in attack_rule or "integrity" in attack_rule:
    raise SystemExit("production attack rule unexpectedly contains integrity")
if f'sha256 = "{expected}"' not in control_rule or control_rule.replace(f'    sha256 = "{expected}",\n', "", 1) != attack_rule:
    raise SystemExit("control differs from the production rule by more than reviewed sha256")

observed = digest(args.diagnostic_archive)
if observed == expected:
    raise SystemExit("replacement window did not change reviewed A")
control_log = args.control_log.read_text(errors="replace")
if args.control_rc == 0:
    raise SystemExit("replacement archive B passed the digest control")
if re.search(rf"Checksum was {re.escape(observed)} but wanted {re.escape(expected)}", control_log) is None:
    raise SystemExit("control failure does not bind observed B and reviewed A")

pre = json.loads(args.pre_admission.read_text())
if pre.get("output_bases_already_warmed") != ["attack", "control"]:
    raise SystemExit("both output bases were not warmed before target admission")
if pre.get("target_repository") != emitter["target_repository"] or pre.get("target_repository_absent_before_admission") is not True:
    raise SystemExit("target repository existed before first admission")
if pre.get("warm_repository") != emitter["warm_repository"] or pre.get("warm_unrelated_repository_materialized_first") is not True:
    raise SystemExit("unrelated production repository did not warm the output bases")

repo = emitter["target_repository"]
source_path = f"external/+_repo_rules+{repo}/proof.binaryproto"
action = args.action.read_text(errors="replace")
if "Mnemonic: CompileProductionPublishedDocs" not in action or source_path not in action:
    raise SystemExit("compiler action does not bind the production external repository")
if action.count(source_path) < 2:
    raise SystemExit("production external protobuf is not both declared and positional compiler input")
if "diagnostic" in action or "copied" in action:
    raise SystemExit("compiler action uses a diagnostic or copied protobuf")
if digest(args.fetched_proto) != digest(args.diagnostic_proto):
    raise SystemExit("Bazel external protobuf differs from the current URL archive member")

readback = json.loads(args.readback.read_text())
files = readback.get("file", [])
if readback.get("source") != "PUBLISHED" or len(files) != 1 or files[0].get("description") != "BCR_TARGET_UNREVIEWED_MODULE_DOCSTRING":
    raise SystemExit("semantic readback lacks the unreviewed target marker")
if files[0]["description"].encode() not in gzip.decompress(args.protobuf.read_bytes()):
    raise SystemExit("compiled protobuf lacks the semantic readback marker")
with tarfile.open(args.site_tar) as archive:
    released = archive.extractfile("modules/proof/1.0.0/documentationinfo.pb.gz").read()
if released != args.protobuf.read_bytes():
    raise SystemExit("releasecompiler changed the documentation protobuf")

receipt = {
    "result": "PASS", "registry_commit": args.registry_commit,
    "frontend_sha": emitter["frontend_commit"], "production_function": emitter["production_function"],
    "production_rule_execution": True, "production_repository_name": repo,
    "production_target_label": emitter["target_label"], "source_url": emitter["target_url"],
    "reviewed_sha256": expected, "downloaded_sha256": observed,
    "attack_integrity_forwarded": False, "control_integrity_forwarded": True,
    "control_result": "REJECTED_REPLACEMENT", "control_expected_sha256": expected, "control_observed_sha256": observed,
    "control_and_attack_same_url": True, "control_and_attack_same_bytes": True,
    "compiler_input_from_production_external_repository": True,
    "compiler_external_path": source_path, "manual_download_used_as_compiler_source": False,
    "fetched_binaryproto_sha256": digest(args.fetched_proto),
    "diagnostic_binaryproto_sha256": digest(args.diagnostic_proto),
    "compiled_source": readback["source"], "compiled_description": files[0]["description"],
    "documentation_protobuf_sha256": digest(args.protobuf), "release_site_sha256": digest(args.site_tar),
    "release_member_byte_identical": True,
    "target_repository_absent_before_admission": True,
    "target_rule_first_admitted_after_replacement": True,
    "warm_unrelated_repository_materialized_first": True,
    "warm_repository": emitter["warm_repository"], "warm_url": emitter["warm_url"],
}
args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
print(json.dumps(receipt, indent=2, sort_keys=True))
