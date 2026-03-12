"""
Primust Artifact Core — Commitment Layer (P6-A) — Python mirror

SHA-256 (default) and Poseidon2 (opt-in via PRIMUST_COMMITMENT_ALGORITHM=poseidon2) commitments.
Poseidon2 uses a pure Python implementation — opt-in only until an audited reference
(e.g. Barretenberg) is validated.

PRIVACY INVARIANT: Raw content NEVER leaves the customer environment.
Only the commitment hash transits to Primust API.
"""

import hashlib
import os
from typing import List, Optional, Tuple

# ── BN254 Field ──

BN254_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617

ZK_IS_BLOCKING = False

# ── Poseidon2 Constants (BN254, t=4, d=5, 4+56+4 rounds) ──

MAT_DIAG4_M_1 = [
    0x10dc6e9c006ea38b04b1e03b4bd9490c0d03f98929ca1d7fb56821fd19d3b6e7,
    0x0c28145b6a44df3e0149b3d0a30b3bb599df9756d4dd9b84a86b38cfb45a740b,
    0x00544b8338791518b2c7645a50392798b21f75bb60e3596170067d00141cac15,
    0x222c01175718386f2e2e82eb122789e352e105a3b8fa852613bc534433ee428b,
]

# Full round constants: 4 beginning + 56 partial (first element only) + 4 ending
RC_FULL_BEGIN = [
    [
        0x19b849f69450b06848da1d39bd5e4a4302bb86744edc26238b0878e269ed23e5,
        0x265ddfe127dd51bd7239347b758f0a1320eb2cc7450acc1dad47f80c8dcf34d6,
        0x199750ec472f1809e0f66a545e1e51624108ac845015c2aa3dfc36bab497d8aa,
        0x157ff3fe65ac7208110f06a5f74302b14d743ea25067f0ffd032f787c7f1cdf8,
    ],
    [
        0x2e49c43c4569dd9c5fd35ac45fca33f10b15c590692f8beefe18f4896ac94902,
        0x0e35fb89981890520d4aef2b6d6506c3cb2f0b6973c24fa82731345ffa2d1f1e,
        0x251ad47cb15c4f1105f109ae5e944f1ba9d9e7806d667ffec6fe723002e0b996,
        0x13da07dc64d428369873e97160234641f8beb56fdd05e5f3563fa39d9c22df4e,
    ],
    [
        0x0c009b84e650e6d23dc00c7dccef7483a553939689d350cd46e7b89055fd4738,
        0x011f16b1c63a854f01992e3956f42d8b04eb650c6d535eb0203dec74befdca06,
        0x0ed69e5e383a688f209d9a561daa79612f3f78d0467ad45485df07093f367549,
        0x04dba94a7b0ce9e221acad41472b6bbe3aec507f5eb3d33f463672264c9f789b,
    ],
    [
        0x0a3f2637d840f3a16eb094271c9d237b6036757d4bb50bf7ce732ff1d4fa28e8,
        0x259a666f129eea198f8a1c502fdb38fa39b1f075569564b6e54a485d1182323f,
        0x28bf7459c9b2f4c6d8e7d06a4ee3a47f7745d4271038e5157a32fdf7ede0d6a1,
        0x0a1ca941f057037526ea200f489be8d4c37c85bbcce6a2aeec91bd6941432447,
    ],
]

RC_PARTIAL = [
    0x0c6f8f958be0e93053d7fd4fc54512855535ed1539f051dcb43a26fd926361cf,
    0x123106a93cd17578d426e8128ac9d90aa9e8a00708e296e084dd57e69caaf811,
    0x26e1ba52ad9285d97dd3ab52f8e840085e8fa83ff1e8f1877b074867cd2dee75,
    0x1cb55cad7bd133de18a64c5c47b9c97cbe4d8b7bf9e095864471537e6a4ae2c5,
    0x1dcd73e46acd8f8e0e2c7ce04bde7f6d2a53043d5060a41c7143f08e6e9055d0,
    0x011003e32f6d9c66f5852f05474a4def0cda294a0eb4e9b9b12b9bb4512e5574,
    0x2b1e809ac1d10ab29ad5f20d03a57dfebadfe5903f58bafed7c508dd2287ae8c,
    0x2539de1785b735999fb4dac35ee17ed0ef995d05ab2fc5faeaa69ae87bcec0a5,
    0x0c246c5a2ef8ee0126497f222b3e0a0ef4e1c3d41c86d46e43982cb11d77951d,
    0x192089c4974f68e95408148f7c0632edbb09e6a6ad1a1c2f3f0305f5d03b527b,
    0x1eae0ad8ab68b2f06a0ee36eeb0d0c058529097d91096b756d8fdc2fb5a60d85,
    0x179190e5d0e22179e46f8282872abc88db6e2fdc0dee99e69768bd98c5d06bfb,
    0x29bb9e2c9076732576e9a81c7ac4b83214528f7db00f31bf6cafe794a9b3cd1c,
    0x225d394e42207599403efd0c2464a90d52652645882aac35b10e590e6e691e08,
    0x064760623c25c8cf753d238055b444532be13557451c087de09efd454b23fd59,
    0x10ba3a0e01df92e87f301c4b716d8a394d67f4bf42a75c10922910a78f6b5b87,
    0x0e070bf53f8451b24f9c6e96b0c2a801cb511bc0c242eb9d361b77693f21471c,
    0x1b94cd61b051b04dd39755ff93821a73ccd6cb11d2491d8aa7f921014de252fb,
    0x1d7cb39bafb8c744e148787a2e70230f9d4e917d5713bb050487b5aa7d74070b,
    0x2ec93189bd1ab4f69117d0fe980c80ff8785c2961829f701bb74ac1f303b17db,
    0x2db366bfdd36d277a692bb825b86275beac404a19ae07a9082ea46bd83517926,
    0x062100eb485db06269655cf186a68532985275428450359adc99cec6960711b8,
    0x0761d33c66614aaa570e7f1e8244ca1120243f92fa59e4f900c567bf41f5a59b,
    0x20fc411a114d13992c2705aa034e3f315d78608a0f7de4ccf7a72e494855ad0d,
    0x25b5c004a4bdfcb5add9ec4e9ab219ba102c67e8b3effb5fc3a30f317250bc5a,
    0x23b1822d278ed632a494e58f6df6f5ed038b186d8474155ad87e7dff62b37f4b,
    0x22734b4c5c3f9493606c4ba9012499bf0f14d13bfcfcccaa16102a29cc2f69e0,
    0x26c0c8fe09eb30b7e27a74dc33492347e5bdff409aa3610254413d3fad795ce5,
    0x070dd0ccb6bd7bbae88eac03fa1fbb26196be3083a809829bbd626df348ccad9,
    0x12b6595bdb329b6fb043ba78bb28c3bec2c0a6de46d8c5ad6067c4ebfd4250da,
    0x248d97d7f76283d63bec30e7a5876c11c06fca9b275c671c5e33d95bb7e8d729,
    0x1a306d439d463b0816fc6fd64cc939318b45eb759ddde4aa106d15d9bd9baaaa,
    0x28a8f8372e3c38daced7c00421cb4621f4f1b54ddc27821b0d62d3d6ec7c56cf,
    0x0094975717f9a8a8bb35152f24d43294071ce320c829f388bc852183e1e2ce7e,
    0x04d5ee4c3aa78f7d80fde60d716480d3593f74d4f653ae83f4103246db2e8d65,
    0x2a6cf5e9aa03d4336349ad6fb8ed2269c7bef54b8822cc76d08495c12efde187,
    0x2304d31eaab960ba9274da43e19ddeb7f792180808fd6e43baae48d7efcba3f3,
    0x03fd9ac865a4b2a6d5e7009785817249bff08a7e0726fcb4e1c11d39d199f0b0,
    0x00b7258ded52bbda2248404d55ee5044798afc3a209193073f7954d4d63b0b64,
    0x159f81ada0771799ec38fca2d4bf65ebb13d3a74f3298db36272c5ca65e92d9a,
    0x1ef90e67437fbc8550237a75bc28e3bb9000130ea25f0c5471e144cf4264431f,
    0x1e65f838515e5ff0196b49aa41a2d2568df739bc176b08ec95a79ed82932e30d,
    0x2b1b045def3a166cec6ce768d079ba74b18c844e570e1f826575c1068c94c33f,
    0x0832e5753ceb0ff6402543b1109229c165dc2d73bef715e3f1c6e07c168bb173,
    0x02f614e9cedfb3dc6b762ae0a37d41bab1b841c2e8b6451bc5a8e3c390b6ad16,
    0x0e2427d38bd46a60dd640b8e362cad967370ebb777bedff40f6a0be27e7ed705,
    0x0493630b7c670b6deb7c84d414e7ce79049f0ec098c3c7c50768bbe29214a53a,
    0x22ead100e8e482674decdab17066c5a26bb1515355d5461a3dc06cc85327cea9,
    0x25b3e56e655b42cdaae2626ed2554d48583f1ae35626d04de5084e0b6d2a6f16,
    0x1e32752ada8836ef5837a6cde8ff13dbb599c336349e4c584b4fdc0a0cf6f9d0,
    0x2fa2a871c15a387cc50f68f6f3c3455b23c00995f05078f672a9864074d412e5,
    0x2f569b8a9a4424c9278e1db7311e889f54ccbf10661bab7fcd18e7c7a7d83505,
    0x044cb455110a8fdd531ade530234c518a7df93f7332ffd2144165374b246b43d,
    0x227808de93906d5d420246157f2e42b191fe8c90adfe118178ddc723a5319025,
    0x02fcca2934e046bc623adead873579865d03781ae090ad4a8579d2e7a6800355,
    0x0ef915f0ac120b876abccceb344a1d36bad3f3c5ab91a8ddcbec2e060d8befac,
]

RC_FULL_END = [
    [
        0x1797130f4b7a3e1777eb757bc6f287f6ab0fb85f6be63b09f3b16ef2b1405d38,
        0x0a76225dc04170ae3306c85abab59e608c7f497c20156d4d36c668555decc6e5,
        0x1fffb9ec1992d66ba1e77a7b93209af6f8fa76d48acb664796174b5326a31a5c,
        0x25721c4fc15a3f2853b57c338fa538d85f8fbba6c6b9c6090611889b797b9c5f,
    ],
    [
        0x0c817fd42d5f7a41215e3d07ba197216adb4c3790705da95eb63b982bfcaf75a,
        0x13abe3f5239915d39f7e13c2c24970b6df8cf86ce00a22002bc15866e52b5a96,
        0x2106feea546224ea12ef7f39987a46c85c1bc3dc29bdbd7a92cd60acb4d391ce,
        0x21ca859468a746b6aaa79474a37dab49f1ca5a28c748bc7157e1b3345bb0f959,
    ],
    [
        0x05ccd6255c1e6f0c5cf1f0df934194c62911d14d0321662a8f1a48999e34185b,
        0x0f0e34a64b70a626e464d846674c4c8816c4fb267fe44fe6ea28678cb09490a4,
        0x0558531a4e25470c6157794ca36d0e9647dbfcfe350d64838f5b1a8a2de0d4bf,
        0x09d3dca9173ed2faceea125157683d18924cadad3f655a60b72f5864961f1455,
    ],
    [
        0x0328cbd54e8c0913493f866ed03d218bf23f92d68aaec48617d4c722e5bd4335,
        0x2bf07216e2aff0a223a487b1a7094e07e79e7bcc9798c648ee3347dd5329d34b,
        0x1daf345a58006b736499c583cb76c316d6f78ed6a6dffc82111e11a63fe412df,
        0x176563472456aaa746b694c60e1823611ef39039b2edc7ff391e6f2293d2c404,
    ],
]


# ── Poseidon2 Permutation (t=4, d=5) ──

def _sbox(x: int) -> int:
    """S-box: x^5 mod p."""
    x2 = (x * x) % BN254_P
    return (x2 * x2 % BN254_P) * x % BN254_P


def _matmul_external_4(state: List[int]) -> List[int]:
    """External (MDS) matrix multiply for t=4."""
    p = BN254_P
    s = state

    t_0 = (s[0] + s[1]) % p
    t_1 = (s[2] + s[3]) % p
    t_2 = (s[1] + s[1] + t_1) % p  # 2*s[1] + t_1
    t_3 = (s[3] + s[3] + t_0) % p  # 2*s[3] + t_0
    t_4 = (t_1 + t_1) % p
    t_4 = (t_4 + t_4 + t_3) % p    # 4*t_1 + t_3
    t_5 = (t_0 + t_0) % p
    t_5 = (t_5 + t_5 + t_2) % p    # 4*t_0 + t_2
    t_6 = (t_3 + t_5) % p
    t_7 = (t_2 + t_4) % p

    return [t_6, t_5, t_7, t_4]


def _matmul_internal_4(state: List[int]) -> List[int]:
    """Internal matrix multiply for t=4: diag * x + sum(x)."""
    p = BN254_P
    s = state
    total = (s[0] + s[1] + s[2] + s[3]) % p
    return [
        (MAT_DIAG4_M_1[i] * s[i] + total) % p
        for i in range(4)
    ]


def poseidon2_permute(state: List[int]) -> List[int]:
    """Full Poseidon2 permutation for BN254, t=4."""
    p = BN254_P
    s = list(state)

    # Initial external matrix
    s = _matmul_external_4(s)

    # 4 full beginning rounds
    for r in range(4):
        rc = RC_FULL_BEGIN[r]
        s = [(s[i] + rc[i]) % p for i in range(4)]
        s = [_sbox(x) for x in s]
        s = _matmul_external_4(s)

    # 56 partial rounds
    for r in range(56):
        s[0] = (s[0] + RC_PARTIAL[r]) % p
        s[0] = _sbox(s[0])
        s = _matmul_internal_4(s)

    # 4 full ending rounds
    for r in range(4):
        rc = RC_FULL_END[r]
        s = [(s[i] + rc[i]) % p for i in range(4)]
        s = [_sbox(x) for x in s]
        s = _matmul_external_4(s)

    return s


# ── Poseidon2 Sponge (matching @zkpassport/poseidon2 FieldSponge) ──

class _FieldSponge:
    """Poseidon2 sponge construction with rate=3, capacity=1, t=4."""

    RATE = 3
    T = 4
    ABSORB = 0
    SQUEEZE = 1

    def __init__(self, domain_iv: int = 0):
        self.state = [0, 0, 0, domain_iv]
        self.cache = [0] * self.RATE
        self.cache_size = 0
        self.mode = self.ABSORB

    def _perform_duplex(self) -> List[int]:
        # Zero-pad the cache
        for i in range(self.cache_size, self.RATE):
            self.cache[i] = 0
        # Add cache into sponge state
        for i in range(self.RATE):
            self.state[i] = (self.state[i] + self.cache[i]) % BN254_P
        self.state = poseidon2_permute(self.state)
        return self.state[:self.RATE]

    def absorb(self, value: int) -> None:
        if self.mode == self.ABSORB and self.cache_size == self.RATE:
            self._perform_duplex()
            self.cache[0] = value
            self.cache_size = 1
        elif self.mode == self.ABSORB and self.cache_size < self.RATE:
            self.cache[self.cache_size] = value
            self.cache_size += 1
        elif self.mode == self.SQUEEZE:
            self.cache[0] = value
            self.cache_size = 1
            self.mode = self.ABSORB

    def squeeze(self) -> int:
        if self.mode == self.SQUEEZE and self.cache_size == 0:
            self.mode = self.ABSORB
            self.cache_size = 0

        if self.mode == self.ABSORB:
            new_output = self._perform_duplex()
            self.mode = self.SQUEEZE
            for i in range(self.RATE):
                self.cache[i] = new_output[i]
            self.cache_size = self.RATE

        result = self.cache[0]
        for i in range(1, self.cache_size):
            self.cache[i - 1] = self.cache[i]
        self.cache_size -= 1
        self.cache[self.cache_size] = 0
        return result


def poseidon2_hash(inputs: List[int]) -> int:
    """Hash a list of field elements using Poseidon2 sponge (fixed-length)."""
    out_len = 1
    iv = (len(inputs) << 64) + (out_len - 1)
    sponge = _FieldSponge(iv)
    for v in inputs:
        sponge.absorb(v)
    return sponge.squeeze()


# ── Byte Conversion ──

def _bytes_to_field_elements(data: bytes) -> List[int]:
    """Convert bytes to BN254 field elements (31-byte chunks, big-endian)."""
    if len(data) == 0:
        return [0]

    elements = []
    chunk_size = 31
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        value = int.from_bytes(chunk, byteorder="big")
        elements.append(value % BN254_P)
    return elements


# ── Core Hash Functions ──

def _poseidon2_bytes(data: bytes) -> str:
    """Poseidon2 hash over arbitrary bytes, matching TS commitment.ts."""
    elements = _bytes_to_field_elements(data)

    state = 0
    for i in range(0, len(elements), 2):
        left = elements[i]
        right = elements[i + 1] if i + 1 < len(elements) else 0
        state = poseidon2_hash([(state + left) % BN254_P, right])

    return "poseidon2:" + format(state, "064x")


def _sha256_bytes(data: bytes) -> str:
    """SHA-256 hash over arbitrary bytes."""
    h = hashlib.sha256(data).hexdigest()
    return "sha256:" + h


def _poseidon2_pair(left: int, right: int) -> int:
    """Poseidon2 hash of two field elements (for Merkle internal nodes)."""
    return poseidon2_hash([left, right])


def _parse_hash_to_field(hash_str: str) -> int:
    """Parse 'algorithm:hex' hash string to field element."""
    colon = hash_str.index(":")
    hex_str = hash_str[colon + 1:]
    return int(hex_str, 16) % BN254_P


# ── Algorithm Resolution ──


def _resolve_algorithm() -> str:
    """Resolve commitment algorithm from env var or default.
    Default is 'sha256'. Poseidon2 is opt-in via PRIMUST_COMMITMENT_ALGORITHM=poseidon2
    until an audited implementation (e.g. Barretenberg) is validated.
    """
    alg = os.environ.get("PRIMUST_COMMITMENT_ALGORITHM")
    if alg == "poseidon2":
        return "poseidon2"
    return "sha256"


def _parse_hash_to_raw_bytes(hash_str: str) -> bytes:
    """Parse 'algorithm:hex' hash string to raw bytes."""
    colon = hash_str.index(":")
    hex_str = hash_str[colon + 1:]
    return bytes.fromhex(hex_str)


# ── Public API ──

CommitmentResult = Tuple[str, str]  # (hash, algorithm)


def commit(data: bytes, algorithm: Optional[str] = None) -> CommitmentResult:
    """
    Compute a commitment hash over input bytes.

    Args:
        data: Raw content bytes (NEVER transmitted)
        algorithm: 'sha256' (default) or 'poseidon2'. If None, uses
                   PRIMUST_COMMITMENT_ALGORITHM env var or defaults to 'sha256'.

    Returns:
        (hash_string, algorithm)
    """
    alg = algorithm if algorithm is not None else _resolve_algorithm()
    if alg == "poseidon2":
        return (_poseidon2_bytes(data), "poseidon2")
    return (_sha256_bytes(data), "sha256")


def commit_output(data: bytes) -> CommitmentResult:
    """Commitment for check output. Uses resolved algorithm."""
    alg = _resolve_algorithm()
    if alg == "poseidon2":
        return (_poseidon2_bytes(data), "poseidon2")
    return (_sha256_bytes(data), "sha256")


def build_commitment_root(
    hashes: List[str], algorithm: Optional[str] = None
) -> Optional[str]:
    """
    Build Merkle root over commitment hashes.
    Uses resolved algorithm (SHA-256 default) for intermediate nodes.

    Returns:
        Merkle root string, or None for empty list.
        Single hash returns unchanged.
    """
    alg = algorithm if algorithm is not None else _resolve_algorithm()
    if len(hashes) == 0:
        return None
    if len(hashes) == 1:
        return hashes[0]

    if alg == "poseidon2":
        return _build_poseidon2_merkle_root(hashes)
    return _build_sha256_merkle_root(hashes)


def _build_poseidon2_merkle_root(hashes: List[str]) -> str:
    layer = [_parse_hash_to_field(h) for h in hashes]

    while len(layer) > 1:
        next_layer = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else layer[i]
            next_layer.append(_poseidon2_pair(left, right))
        layer = next_layer

    return "poseidon2:" + format(layer[0], "064x")


def _build_sha256_merkle_root(hashes: List[str]) -> str:
    layer = [_parse_hash_to_raw_bytes(h) for h in hashes]

    while len(layer) > 1:
        next_layer = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else layer[i]
            next_layer.append(hashlib.sha256(left + right).digest())
        layer = next_layer

    return "sha256:" + layer[0].hex()


def select_proof_level(stage_type: str) -> str:
    """
    Select the proof level for a given stage type.

    TODO(zk-integration): Restore deterministic_rule/policy_engine to "mathematical"
    when ZK proof integration is live.

    deterministic_rule → execution (mathematical when ZK wired)
    zkml_model         → verifiable_inference
    ml_model           → execution
    statistical_test   → execution
    custom_code        → execution
    witnessed          → witnessed
    policy_engine      → execution (mathematical when ZK wired)
    """
    mapping = {
        "deterministic_rule": "execution",
        "zkml_model": "verifiable_inference",
        "ml_model": "execution",
        "statistical_test": "execution",
        "custom_code": "execution",
        "witnessed": "witnessed",
        "policy_engine": "execution",
    }
    result = mapping.get(stage_type)
    if result is None:
        raise ValueError(f"Unknown stage type: {stage_type}")
    return result
