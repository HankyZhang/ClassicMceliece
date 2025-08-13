# Classic McEliece Algorithm Explained in Detail

## CONTENT
### **Chapter 1: Key Generation Phase**
### **Chapter 2: Encapsulation Phase**
### **Chapter 3: Decapsulation Phase**
***

## 01. Key Generation Phase

The goal of the key generation phase is to produce a public key $T$ and a private key $(δ, c, g, a, s)$.

*   **Public Key**: $T$
*   **Private Key**: $(δ, c, g, a, s)$
    *   $c = (c_{mt-μ}, ..., c_{mt-1})$
    *   $α = (α'₀, ..., α'_{n-1}, α_n, ..., α_{q-1})$

---

### 1. Key Generation Steps

#### 1.1 Generate a uniformly random *l*-bit string $δ$.
This $δ$ serves as the seed for a Pseudorandom Generator (PRG).

#### 1.2 Run $SeededKeyGen(δ)$ to generate the public and private keys.

**1.2.1** Compute $E = PRG(δ)$, which is an $n + σ₂q + σ₁t + l$ bit string.

**1.2.2** Define $δ'$ as the last $l$ bits of $E$.

**1.2.3** Define $s$ as the first $n$ bits of $E$.

**1.2.4** Use the next $σ₂q$ bits from $E$ to compute $α₀, ..., α_{q-1}$ via the $FieldOrdering$ algorithm. If it fails, set $δ ← δ'$ and restart the algorithm.

**1.2.5** Use the next $σ₁t$ bits from $E$ to compute $g$ via the $Irreducible$ algorithm. If it fails, set $δ ← δ'$ and restart the algorithm.
> Note: As mentioned in Chapter 9 of the code and documentation, this step also involves calculating the control bits for the Benes network corresponding to the permutation $π(i)$ stored in the private key $sk$. This is handled by the $controlbitsfrompermutation$ function.

**1.2.6** Define $Γ = (g, α₀, α₁, ..., α_{n-1})$. (Note that $α_n, ..., α_{q-1}$ are not used in $Γ$).

**1.2.7** Compute $(T, c_{mt-μ}, ..., c_{mt-1}, Γ') ← MatGen(Γ)$. If it fails, set $δ ← δ'$ and restart the algorithm.

**1.2.8** Write $Γ'$ as $(g, α'₀, α'₁, ..., α'_{n-1})$.

**1.2.9** Output $T$ as the public key and $(δ, c, g, a, s)$ as the private key, where $c = (c_{mt-μ}, ..., c_{mt-1})$ and $a = (α'₀, ..., α'_{n-1}, α_n, ..., α_{q-1})$.

---

### 1. Key Generation Phase --- 1.2.4 FieldOrdering Algorithm

This algorithm generates the support elements for the Goppa code.

1.  Take the first $σ₂$ input bits $b₀, b₁, ..., b_{σ₂-1}$ and interpret them as an integer $a₀$ ($σ₂$ bits):
    $a₀ = b₀ + 2b₁ + ... + 2^(σ₂-1) * b_{σ₂-1}$. Repeat this process to generate $a₁, ..., a_{q-1}$.
2.  If there are any duplicate values among $a₀, a₁, ..., a_{q-1}$, return $⊥$ (failure).
3.  Sort the pairs $(aᵢ, i)$ lexicographically to get $(α_{π(i)}, π(i))$, where $π$ is a permutation of ${0, 1, ..., q-1}$.
4.  Define $αᵢ$ as a polynomial: $αᵢ = Σ_{j=0}^{m-1} π(i)ⱼ · z^(m-1-j)$.
    > Here, $π(i)ⱼ$ represents the j-th least significant bit of $π(i)$. The finite field $F_q$ is constructed as $F₂[z]/f(z)$.

---

### 1. Key Generation Phase --- 1.2.5 Irreducible Algorithm (Computing g)

This algorithm takes a $σ₁t$-bit input string $d₀, d₁, ..., d_{σ₁t-1}$ and outputs either $⊥$ (failure) or a monic, irreducible polynomial $g$ of degree $t$ in $F_q[x]$.

1.  For each $j ∈ {0, 1, ..., t-1}$, define $βⱼ = Σ_{i=0}^{m-1} d_{σ₁j+i} zⁱ$.
    > Within each block of $σ₁$ input bits, only the first $m$ bits are used. The algorithm ignores the remaining bits.

2.  Define $β = β₀ + β₁y + ... + β_{t-1}y^(t-1) ∈ F_q[y]/F(y)$. This is used to construct a matrix.

3.  Compute the minimal polynomial $g$ of $β$ over $F_q$.
    > By definition, $g$ is monic and irreducible, and $g(β) = 0$.

    *   **Construct a linearly dependent set:** We know $g(x)$ has degree $t$. Therefore, the $t+1$ elements $1, β, β², ..., β^t$ must be linearly dependent in $F_(2^m)t$. This means there exist coefficients $g₀, g₁, ..., g_t ∈ F_2m$, not all zero, such that:
        $g₀·1 + g₁·β + g₂·β² + ... + g_t·β^t = 0$
        Since $g(x)$ is monic, we can set $g_t = 1$.

    *   **Build the matrix:** Express each power $β^k$ (for $k = 0, ..., t$) as a polynomial in $y$ of degree less than $t$:
        $β^k = b_{k,0} + b_{k,1}y + ... + b_{k,t-1}y^(t-1)$
        By expanding the linear dependency equation and setting the coefficient of each power of $y$ to zero, we obtain a $t x t$ system of linear equations for the unknown coefficients $g₀, ..., g_{t-1}$.

    *   **Matrix Form:** The system of equations can be written in matrix form:
        ```
        [ b₀,₀   b₁,₀   ...   b_{t-1},₀ ] [ g₀ ]   [ b_{t,0}   ]
        [ b₀,₁   b₁,₁   ...   b_{t-1},₁ ] [ g₁ ]   [ b_{t,1}   ]
        [  :      :    ...      :     ] [ :  ] =-[   :     ]
        [ b₀,t-₁ b₁,t-₁ ...   b_{t-1},t-₁] [g_{t-1}] [ b_{t,t-1} ]
        ```

    *   **Solve the System:** Use a method like Gaussian elimination over the field $F_2m$ to solve this linear system and find the unique solution $g₀, g₁, ..., g_{t-1}$.

    *   **Construct g(x):** The final Goppa polynomial is:
        $g(x) = g₀ + g₁x + ... + g_{t-1}x^(t-1) + x^t$

4.  If the degree of $g$ is $t$, return $g$. Otherwise, return $⊥$.
    > This check is equivalent to determining if the matrix after Gaussian elimination has a non-zero pivot in every column.

5.  This step is not part of the $Irreducible$ algorithm itself but is mentioned on slide 10. The $FieldOrdering$ algorithm (1.2.4) outputs $(α₀, α₁, ..., α_{q-1})$.

---

### 1. Key Generation Phase --- $controlbitsfrompermutation$

This algorithm is used to compute the control bits for a Benes network to perform a permutation, which is crucial for security and efficiency.

*   **Problem Context**: We need to reorder a large set of data (e.g., an array). A naive approach of creating a new array and copying elements can have two major drawbacks:
    *   **Security**: In cryptography, data access patterns (e.g., the order of reading memory addresses) can leak secret information. This is known as a **Timing Attack**.
    *   **Efficiency**: For hardware implementations, specialized circuits are often much faster than general-purpose memory read/write operations.

*   **Permutation Networks**: These are specialized hardware structures designed to solve this problem. They consist of a series of basic "switches" that can realize any permutation of the input data. The **Beneš network** is a classic and efficient type of permutation network. To make the network perform a specific permutation (e.g., transform $(a, b, c, d)$ to $(c, a, d, b)$), each switch in the network must be set to the correct state (either pass-through or swap inputs). These settings are the **control bits**.

*   **Core Problem**: Given a desired permutation $π$, how do we quickly and correctly compute the set of control bits needed to configure the network?

#### Beneš Network Decomposition

A key property of a Beneš network for $n = 2^k$ inputs is that its permutation $π$ can be decomposed into a composition of three sub-operations:
$π = F ◦ M ◦ L$
(Function composition is executed from right to left).

*   **L (Input Side)**: The first layer of switches, controlled by a set of bits $l$ (lastcontrol). It performs conditional swaps on adjacent input pairs $(x, x+1)$, specifically $(0,1), (2,3), (4,5), ...$.
*   **M (Middle)**: The core of the network. After the $L$ operation, the data enters two smaller, independent Beneš networks, each of size $n/2$. $M$ represents the permutation performed by these two sub-networks. $M$ has a crucial **parity-preserving property**: even-indexed inputs are only ever sent to even-indexed outputs, and odd-indexed inputs are only ever sent to odd-indexed outputs. Because of this, $M$ can be decomposed into two independent permutations of size $n/2$:
    *   $M₀$: Permutes the even-indexed positions.
    *   $M₁$: Permutes the odd-indexed positions.
*   **F (Output Side)**: The final layer of switches, controlled by a set of bits $f$ (firstcontrol). Its function is similar to $L$, performing conditional swaps on adjacent positions $(x, x+1)$ to complete the final steps of the permutation.

**The core task of the algorithm is to compute the correct $f$ and $l$ and deduce the sub-permutations $M₀$ and $M₁$. Then, the same algorithm is called recursively on $M₀$ and $M₁$ until the network size is reduced to 2.**

#### Algorithm Steps

**Step 1: Introduce the $XbackXforth$ Transform (Define π')**
The algorithm first applies a clever transformation to the original permutation $π$ to get a new permutation $π'$.
$π' = XbackXforth(π)$, defined as $π'(x) = π(π⁻¹(x ⊕ 1) ⊕ 1)$
where $⊕$ is the bitwise XOR operation. This gives $π'$ a useful property (Theorem 4.4):
$cyclemin(π')(x ⊕ 1) = cyclemin(π')(x) ⊕ 1$
This means that if we calculate the "cycle minimum" for an even number $x$, we can find the cycle minimum for its odd neighbor $x ⊕ 1$ with a single XOR operation, effectively halving the computation.

**Step 2: Compute Cycle Minimum ($cyclemin$)**
The goal is to compute $c(x) = cyclemin(π')(x)$.
*   **Definition**: A permutation consists of disjoint cycles. $cyclemin(π')(x)$ refers to the smallest element in the cycle that contains $x$. This smallest value is called the **cycle leader** of $x$.
*   **Computation ($fastcyclemin$)**: This is an iterative process suitable for parallelization.
    *   Let $c⁰(x) = x$
    *   $c₁(x) = min(c⁰(x), c⁰(π'(x))) = min(x, π'(x))$
    *   $c₂(x) = min(c₁(x), c₁(π'²(x)))$ (This finds the minimum among $x, π'(x), π'²(x), π'³(x)$)
    *   ...
    *   $cᵢ(x) = min(cᵢ₋₁(x), cᵢ₋₁(π'^(2^(i-1)))(x))$
    For an input size $n = 2^m$, after $m-1$ iterations, $c_{m-1}(x)$ will find the minimum value in the entire cycle containing $x$.

**Step 3: Compute $firstcontrol$ (f)**
$fⱼ = c(2j) mod 2$ (for $j$ from 0 to $n/2 - 1$)
The $j$-th control bit $fⱼ$ is simply the parity (0 for even, 1 for odd) of the cycle leader $c(2j)$ of the $j$-th even number $2j$.

**Step 4: Compute $lastcontrol$ (l)**
The calculation for $l$ is slightly more complex, depending on both the original permutation $π$ and the $F$ operation (defined by $f$).
$lₖ = F(π(2k)) mod 2$ (for $k$ from 0 to $n/2 - 1$)
1.  Take the $k$-th even number $2k$.
2.  Find where the original permutation $π$ maps it: $π(2k)$.
3.  Apply the $F$ operation to this result: $F(y) = y ⊕ f[y/2]$.
4.  The parity of the final result is $lₖ$.

**Step 5: Compute and Decompose the Middle Permutation $M$**
With $F$ and $L$ known, $M$ can be derived from the relation $π = F ◦ M ◦ L$:
$M = F⁻¹ ◦ π ◦ L⁻¹$
Since $F$ and $L$ are composed of conditional swaps, they are their own inverses ($F⁻¹ = F$, $L⁻¹ = L$). So:
$M = F ◦ π ◦ L$
Theorem 5.5 guarantees that this $M$ is parity-preserving. It can therefore be decomposed into two sub-permutations:
*   $M₀(j) = M(2j) / 2$
*   $M₁(j) = (M(2j + 1) - 1) / 2$

**Recursion and Termination**
*   **Recursive Call**: The algorithm is now called on the two new permutations $M₀$ and $M₁$ (of size $n/2$) to repeat steps 1-5 and find their respective control bits.
*   **Termination Condition**: The recursion stops when $n = 2$. The permutation is either $(0,1) -> (0,1)$ or $(0,1) -> (1,0)$, and the control bit is simply $π[0]$.
*   **Combined Result**: The final, complete control bit sequence for the $n$-input network is constructed by concatenating the results: the bits for $f$, followed by the interleaved bits from the recursive calls on $M₀$ and $M₁$, followed by the bits for $l$.

---

### 1. Key Generation Phase --- 1.2.5 Computing the Systematic Form

This section describes how the public key matrix $T$ is derived from the Goppa code's parity-check matrix.

#### Case 1: Systematic Form $(μ, ν) = (0,0)$

1.  Compute the $t x n$ matrix $M = {h_{i,j}}$ over $F_q$, where $h_{i,j} = aⱼⁱ / g(aⱼ)$, for $i = 0, ..., t-1$ and $j = 0, ..., n-1$.
2.  Expand this into a binary $mt x n$ matrix $N$ by replacing each entry $u₀ + u₁z + ... + u_{m-1}z^(m-1)$ of $M$ with an $m$-bit column vector $(u₀, u₁, ..., u_{m-1})ᵀ$.
3.  Reduce $N$ to systematic form $(I_{mt} | T)$, where $I_{mt}$ is the $mt x mt$ identity matrix. If this fails, return $⊥$. The right-hand part $T$ is a portion of the public key.
4.  Return $(T, Γ)$.

#### The Goppa Code Parity-Check Matrix (H)

*   **Phase 1: Initial Form over $GF(2^m)$**
    The initial parity-check matrix $H$ is constructed as:
    
    All operations (addition, multiplication, inversion) are performed in the finite field $GF(2^m)$.

*   **Phase 2: Conversion to a Binary Matrix**
    The matrix $H$ has elements from $GF(2^m)$, not the bits $0$ and $1$ ($GF(2)$) that computers handle directly. A "trace construction" is used for conversion.
    *   $GF(2^m)$ can be viewed as an $m$-dimensional vector space over $GF(2)$. This means any element of $GF(2^m)$ can be uniquely represented as an $m$-bit binary vector.
    *   **Conversion Process**:
        1.  Expand each row of $H$ into $m$ rows.
        2.  Replace each element (from $GF(2^m)$) in the original matrix with its corresponding $m x 1$ binary column vector.
    *   This results in a binary $mt x n$ parity-check matrix $H_bin$.
    *   Using Gaussian elimination, $H_bin$ is converted to systematic form:
        $H_sys = [I | T]$
        where $I$ is an $mt x mt$ identity matrix and $T$ is the $mt x (n-mt)$ public key matrix.

#### Case 2: Semi-Systematic Form (General μ, ν)
For the general case, the algorithm produces a matrix in semi-systematic form.

1.  Steps 1 and 2 (calculating $M$ and $N$) are the same as in the systematic case.
2.  Reduce $N$ to $(μ, ν)$-semi-systematic form to get matrix $H'$. If this fails, return $⊥$.
    > In this form, for $0 ≤ i < mt - μ$, the $i$-th row has its leading $1$ at column $cᵢ = i$. For the remaining rows, the leading $1$s are at columns $cᵢ$ where $mt - μ ≤ c_{mt-μ} < ... < c_{mt-1} < mt - μ + ν$.
3.  Set $(α'₀, ..., α'_{n-1}) ← (α₀, ..., α_{n-1})$.
4.  For $i$ from $mt - μ$ to $mt - 1$ (in order), swap column $i$ with column $cᵢ$ in $H'$. Simultaneously, swap $a'ᵢ$ and $a'_{cᵢ}$.
    > After this swap, the $i$-th row has its leading $1$ in the $i$-th column. If $cᵢ = i$, no swap is performed.
5.  The matrix $H'$ is now in the full systematic form $(I_{mt} | T)$. The algorithm returns $(T, c_{mt-μ}, ..., c_{mt-1}, Γ')$, where $Γ'$ contains the modified support elements.

***

## 02. Encapsulation Phase

The randomized $Encap$ algorithm takes the public key $T$ as input and outputs a ciphertext $C$ and a session key $K$.

#### Algorithm for non-$pc$ parameter sets:

1.  Generate a vector $e ∈ F₂ⁿ$ of weight $t$ using the $FixedWeight$ algorithm.
2.  Compute $C = Encode(e, T)$.
3.  Compute $K = Hash(1, e, C)$.
4.  Output ciphertext $C$ and session key $K$.

#### Algorithm for $pc$ parameter sets:

1.  Generate a vector $e ∈ F₂ⁿ$ of weight $t$ using the $FixedWeight$ algorithm.
2.  Compute $C₀ = Encode(e, T)$.
3.  Compute $C₁ = Hash(2, e)$. Let $C = (C₀, C₁)$.
4.  Compute $K = Hash(1, e, C)$.
5.  Output ciphertext $C$ and session key $K$.

---

### 2. Encapsulation Phase --- 2.1 FixedWeight()

This algorithm outputs a vector $e ∈ F₂ⁿ$ with Hamming weight $t$.

1.  Generate $σ₁τ$ uniformly random bits, where $τ$ is a pre-calculated integer $τ ≥ t$.
2.  For each $j ∈ {0, 1, ..., τ-1}$, define $dⱼ$ by taking a block of $σ₁$ bits and interpreting the first $m$ of them as an integer.
3.  Define $a₀, a₁, ..., a_{t-1}$ as the first $t$ unique entries selected from $d₀, d₁, ..., d_{τ-1}$ in the range ${0, 1, ..., n-1}$. If fewer than $t$ unique entries are found, restart the algorithm.
4.  If there are any duplicate elements among $a₀, a₁, ..., a_{t-1}$, restart.
5.  Define the weight-$t$ vector $e = (e₀, e₁, ..., e_{n-1}) ∈ F₂ⁿ$ such that for each $i$, $e_{aᵢ} = 1$.
6.  Return $e$.

---

### 2. Encapsulation Phase --- 2.2 Encode(e, T)

This algorithm takes two inputs: a weight-$t$ column vector $e ∈ F₂ⁿ$ and the public key $T$, which is an $mt x k$ matrix over $F₂$. It outputs a vector $C ∈ F₂ᵐᵗ$.

1.  Define the public parity-check matrix $H = (I_{mt} | T)$.
2.  Compute and return $C = He ∈ F₂ᵐᵗ$.

***

## 03. Decapsulation Phase

The $Decap$ algorithm takes a ciphertext $C$ and the private key as input and outputs a session key $K$.

#### Algorithm for non-$pc$ parameter sets:

1.  Set $b ← 1$.
2.  Extract $s ∈ F₂ⁿ$ and $Γ' = (g, α'₀, ..., α'_{n-1})$ from the private key.
3.  Compute $e ← Decode(C, Γ')$. If $e = ⊥$ (decoding failure), set $e ← s$ and $b ← 0$.
4.  Compute $K = Hash(b, e, C)$.
5.  Output session key $K$.

#### Algorithm for $pc$ parameter sets:

1.  Split the ciphertext $C$ into $(C₀, C₁)$, where $C₀ ∈ F₂ᵐᵗ$. Set $b ← 1$.
2.  Extract $s ∈ F₂ⁿ$ and $Γ' = (g, α'₀, ..., α'_{n-1})$ from the private key.
3.  Compute $e ← Decode(C₀, Γ')$. If $e = ⊥$, set $e ← s$ and $b ← 0$.
4.  Compute $C'₁ = Hash(2, e)$.
5.  If $C'₁ ≠ C₁$, set $e ← s$ and $b ← 0$.
6.  Compute $K = Hash(b, e, C)$.
7.  Output session key $K$.

---

### 3. Decapsulation Phase --- 3.3 Decode(C, Γ')

The $Decode$ function attempts to decode a syndrome $C ∈ F₂ᵐᵗ$ into an error word $e$ of Hamming weight $wt(e) = t$ such that $C = He$. If it cannot find such a word, it returns failure ($⊥$).

The function uses the private key components:
*   $Γ'$ has the form $(g, α'₀, ..., α'_{n-1})$.
*   $g$ is a monic, irreducible Goppa polynomial of degree $t$ loaded from $sk$.
*   $α'₀, ..., α'_{n-1}$ are distinct elements of $F_q$, which form the support set $L$. The permutation to generate these is reconstructed from the Benes network control bits stored in $sk$.

**Algorithm:**
1.  Extend $C$ with $k$ zeros to form $v = (C, 0, ..., 0) ∈ F₂ⁿ$.
2.  Find the unique codeword $c ∈ F₂ⁿ$ such that $(1) Hc = 0$ and $(2)$ the Hamming distance between $c$ and $v$ is $≤ t$. If no such $c$ exists, return $⊥$.
3.  Set $e = v + c$.
4.  If $wt(e) = t$ and $C = He$, return $e$. Otherwise, return $⊥$.

---

### 3. Decapsulation Phase --- 3.3.1 Finding $c$ (Decoding)

#### Phase 1: Compute Syndromes and Derive the Key Equation

1.  **Syndrome Definition**: Assume the Goppa code is defined by the polynomial $g(x)$ and support set $L = {α₀, ..., α_{n-1}}$. If an error occurs at a set of positions $I$, the $j$-th component of the syndrome vector $s = (s₀, ..., s_{2t-1})$ is:
    $sⱼ = Σ_{i∈I} αᵢʲ / g(αᵢ)²$
    For convenience, this is often expressed as a formal power series called the **syndrome polynomial**:
    $S(z) = Σ_{j=0}^{∞} sⱼ zʲ$

2.  **Error-Locator Polynomial $σ(z)$**: This polynomial's roots reveal the error locations.
    $σ(z) = Π_{i∈I} (1 - αᵢz)$
    *   The reciprocal of its roots, $1/αᵢ$, are the support elements corresponding to the error locations.
    *   Its degree $deg(σ(z))$ is the number of errors, $|I|$. Since the system can correct up to $t$ errors, $deg(σ(z)) ≤ t$.
    *   Its constant term is $σ(0) = 1$.

3.  **Key Equation Derivation**: By multiplying $σ(z)$ and $S(z)$, we arrive at the **Key Equation** of decoding theory:
    $σ(z)S(z) = ω(z)$
    where $ω(z)$ is the **error-evaluator polynomial**. The degree of $ω(z)$ is less than $t$.

4.  **Meaning (Connection to LFSRs)**: The Key Equation implies that the syndrome sequence ${sₖ}$ can be generated by a Linear Feedback Shift Register (LFSR). For $k ≥ L$ (where $L$ is the number of errors), we have:
    $sₖ + σ₁s_{k-1} + ... + σ_L s_{k-L} = 0$
    This means that from term $L$ onwards, each syndrome term can be calculated as a fixed linear combination of the previous $L$ terms. The coefficients of this linear relationship, $(σ₁, ..., σ_L)$, are precisely the coefficients of the error-locator polynomial $σ(z)$. The problem of finding $σ(z)$ is equivalent to finding the minimal polynomial of the syndrome sequence.

#### Phase 2: Solving with the Berlekamp-Massey (BM) Algorithm

The BM algorithm is an efficient method to find the shortest LFSR (and thus the minimal polynomial $σ(z)$) for a given sequence $s₀, s₁, ..., s_{N-1}$.

**Key Variables:**
*   $C(z)$: The current best guess for $σ(z)$.
*   $L$: The length (degree) of the current LFSR/$C(z)$.
*   $d$: The discrepancy (error) when predicting the next sequence element.
*   $B(z)$: A "backup" polynomial from the last time $L$ was updated.
*   $b$: The discrepancy associated with $B(z)$.
*   $m$: A counter for steps since the last $L$ update.

**Algorithm Iteration (at step N):**
1.  **Calculate Discrepancy $d_N$**:
    $d_N = s_N + Σ_{i=1}^{L} Cᵢ s_{N-i}$

2.  **Check Discrepancy**:
    *   **If $d_N = 0$**: The prediction is correct. $C(z)$ is still valid. No changes are needed. Move to the next step $N+1$.
    *   **If $d_N ≠ 0$**: Prediction failed. $C(z)$ must be corrected. The core update formula is:
        $C_{new}(z) = C_{old}(z) - d_N · b⁻¹ · z · B(z)$
        (Note: the slides use $z^(N-m)$, but a simplified $z$ term is often used in basic descriptions. The core idea is to "patch" the current polynomial using a scaled and shifted version of a previous good polynomial).

3.  **Update State Variables (only if $d_N ≠ 0$)**:
    *   **If $2L ≤ N$**: The current length $L$ is "too short" to explain the sequence. We must increase the length.
        1.  $L_{new} = N + 1 - L_{old}$
        2.  Update the backup state: The old $C(z)$ and $d_N$ become the new "best snapshot".
            *   $B(z) ← C_{old}(z)$
            *   $b ← d_N$
            *   $m ← N$
    *   **If $2L > N$**: The length $L$ is still "long enough". We only updated the coefficients of $C(z)$, not its degree. Do not update $L$, $B(z)$, or $b$.

#### Phase 3: Find the Roots of $σ(z)$

Once the BM algorithm terminates, we have the error-locator polynomial $σ(z)$. The final step is to find the error locations.
1.  **Iterate through all possible locations**: For each index $j$ from $0$ to $n-1$:
    a. Get the corresponding support element $αⱼ$.
    b. Evaluate $σ(z)$ at $z = αⱼ⁻¹$.
2.  **Check the result**:
    *   If $σ(αⱼ⁻¹) = 0$, we have found a root. This means an error occurred at position $j$.
    *   If $σ(αⱼ⁻¹) ≠ 0$, there is no error at position $j$.
3.  **Record Error Locations**: Create a list of all indices $j$ for which the check in step 2 was true. This list is the set of error positions $I$, which defines the error vector $e$.

