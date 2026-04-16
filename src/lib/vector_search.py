import numpy as np
from scipy.linalg import hadamard

class TurboKVCache:
    def __init__(self, head_dim=64, k_bits=4, v_bits=2):
        self.head_dim = head_dim
        self.k_bits = k_bits
        self.v_bits = v_bits
        
        # Standard Hadamard matrix for rotation
        self.H = hadamard(head_dim) / np.sqrt(head_dim)
        
        # Simulated cache storage (quantized integers)
        self.k_cache = [] # Stores (q_radii, q_angles, params)
        self.v_cache = [] # Stores (q_values, scale)

    def _polar_quant(self, vector, bits):
        """TurboQuant Step: Rotation -> Polar -> Quant"""
        # 1. Rotate to remove outliers
        rotated = self.H @ vector
        
        # 2. Polar Transform (on vector pairs)
        coords = rotated.reshape(-1, 2)
        radii = np.sqrt(np.sum(coords**2, axis=1))
        angles = np.arctan2(coords[:, 1], coords[:, 0])
        
        # 3. Quantize
        levels = 2**bits
        q_r = np.round((radii / (radii.max() + 1e-9)) * (levels - 1)).astype(np.uint8)
        q_a = np.round(((angles + np.pi) / (2 * np.pi)) * (levels - 1)).astype(np.uint8)
        return q_r, q_a, radii.max()

    def add_token(self, k_vec, v_vec):
        """Adds a new token's KV pair to the compressed cache"""
        # Compress Key (K) using PolarQuant
        q_rk, q_ak, r_max = self._polar_quant(k_vec, self.k_bits)
        self.k_cache.append((q_rk, q_ak, r_max))
        
        # Compress Value (V) using simple scalar quant (since it's resilient)
        scale = np.max(np.abs(v_vec))
        q_v = np.round((v_vec / (scale + 1e-9)) * (2**(self.v_bits-1) - 1)).astype(np.int8)
        self.v_cache.append((q_v, scale))

    def get_kv(self, index):
        """Retrieves and dequantizes a KV pair for attention calculation"""
        # Dequantize K (The 'Address')
        qr, qa, r_max = self.k_cache[index]
        r = (qr / (2**self.k_bits - 1)) * r_max
        a = (qa / (2**self.k_bits - 1)) * (2 * np.pi) - np.pi
        
        rotated_k = np.stack([r * np.cos(a), r * np.sin(a)], axis=1).flatten()
        k_final = self.H.T @ rotated_k # Inverse Rotation
        
        # Dequantize V (The 'Content')
        qv, scale = self.v_cache[index]
        v_final = (qv.astype(np.float32) / (2**(self.v_bits-1) - 1)) * scale
        
        return k_final, v_final

class TurboVectorStore:
    def __init__(self, dim=64, bits=4):
        self.dim = dim
        self.bits = bits
        self.H = hadamard(dim) / np.sqrt(dim)
        self.compressed_keys = []
        
    def add_key(self, vector):
        """TurboQuant: Rotate -> Polar -> Store"""
        rotated = self.H @ vector
        # Convert to Polar (Radius & Angle)
        coords = rotated.reshape(-1, 2)
        radii = np.sqrt(np.sum(coords**2, axis=1))
        angles = np.arctan2(coords[:, 1], coords[:, 0])
        
        # Quantize to 4-bit levels
        levels = 2**self.bits
        q_r = np.round((radii / (radii.max() + 1e-9)) * (levels - 1)).astype(np.uint8)
        q_a = np.round(((angles + np.pi) / (2 * np.pi)) * (levels - 1)).astype(np.uint8)
        
        self.compressed_keys.append({
            'q_r': q_r, 'q_a': q_a, 'r_max': radii.max()
        })

    def search(self, query_vector, top_k=3):
        """
        TurboSearch: Rotates the HIGH-PRECISION query once, 
        then compares to LOW-PRECISION keys.
        """
        # 1. Rotate Query once (O(d log d))
        q_rot = self.H @ query_vector
        
        results = []
        for idx, key in enumerate(self.compressed_keys):
            # 2. Fast Dequantize-on-the-fly (Inner Product)
            # Reconstruct Polar in-memory
            r = (key['q_r'] / (2**self.bits - 1)) * key['r_max']
            a = (key['q_a'] / (2**self.bits - 1)) * (2 * np.pi) - np.pi
            
            # Reconstruct rotated Cartesian
            k_rot = np.stack([r * np.cos(a), r * np.sin(a)], axis=1).flatten()
            
            # 3. Compute Inner Product in rotated space (Preserved by Hadamard)
            # Dot(Q, K) == Dot(H@Q, H@K)
            score = np.dot(q_rot, k_rot)
            results.append((idx, score))
        
        return sorted(results, key=lambda x: x[1], reverse=True)[:top_k]

# --- Demo: Searching the M5 Memory ---
store = TurboVectorStore(dim=64, bits=4)

# 1. Store "Code Snippets" (Simulated as vectors)
snippets = ["Auth Logic", "DB Schema", "UI Component", "API Route"]
for _ in range(len(snippets)):
    store.add_key(np.random.randn(64))

# 2. Search for "DB Schema" using a high-precision query
query = np.random.randn(64)
top_results = store.search(query, top_k=2)

#print(f"Top Semantic Match ID: {top_results[0][0]} with score {top_results[0][1]:.4f}")
