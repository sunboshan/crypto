defmodule Crypto.Hash.SHA512 do
  @moduledoc """
  Implement SHA384/512 hash function according to RFC 6234.
  """

  import Bitwise

  @word 0xffffffffffffffff

  # SHA512 initial hash
  @h0 0x6a09e667f3bcc908
  @h1 0xbb67ae8584caa73b
  @h2 0x3c6ef372fe94f82b
  @h3 0xa54ff53a5f1d36f1
  @h4 0x510e527fade682d1
  @h5 0x9b05688c2b3e6c1f
  @h6 0x1f83d9abfb41bd6b
  @h7 0x5be0cd19137e2179

  # SHA384 initial hash
  @i0 0xcbbb9d5dc1059ed8
  @i1 0x629a292a367cd507
  @i2 0x9159015a3070dd17
  @i3 0x152fecd8f70e5939
  @i4 0x67332667ffc00b31
  @i5 0x8eb44a8768581511
  @i6 0xdb0c2e0d64f98fa7
  @i7 0x47b5481dbefa4fa4

  @doc """
  Calculate SHA512 hash value for a given bitstring.

  Example:

      iex> SHA512.hash("abc")
      <<221, 175, 53, 161, 147, 97, 122, 186, 204, 65, 115, 73, 174, 32, 65, 49, 18, 230, 250, 78, 137, 169, 126, 162, 10, 158, 238, 230, 75, 85, 211, 154, 33, 146, 153, 42, 39, 79, 193, 168, 54, 186, 60, 35, 163, 254, 235, 189, 69, 77, 68, 35, 100, 60, 232, 14, 42, 154, 201, 79, 165, 76, 164, 159>>
      iex> SHA512.hash(<<1, 2, 3>>)
      <<39, 134, 76, 197, 33, 154, 149, 26, 122, 110, 82, 184, 200, 221, 223, 105, 129, 208, 152, 218, 22, 88, 217, 98, 88, 200, 112, 178, 200, 141, 251, 203, 81, 132, 26, 234, 23, 42, 40, 186, 250, 106, 121, 115, 17, 101, 88, 70, 119, 6, 96, 69, 201, 89, 237, 15, 153, 41, 104, 141, 4, 222, 252, 41>>
  """
  @spec hash(bitstring) :: binary
  def hash(binary) do
    {a, b, c, d, e, f, g, h} = (for <<block::1024 <- padding(binary)>>, do: <<block::1024>>)
      |> Enum.reduce({@h0, @h1, @h2, @h3, @h4, @h5, @h6, @h7}, &do_hash(&1, &2))
    <<a::64, b::64, c::64, d::64, e::64, f::64, g::64, h::64>>
  end

  @doc """
  Calculate SHA384 hash value for a given bitstring.

  Example:

      iex> SHA512.hash384("abc")
      <<203, 0, 117, 63, 69, 163, 94, 139, 181, 160, 61, 105, 154, 198, 80, 7, 39, 44, 50, 171, 14, 222, 209, 99, 26, 139, 96, 90, 67, 255, 91, 237, 128, 134, 7, 43, 161, 231, 204, 35, 88, 186, 236, 161, 52, 200, 37, 167>>
      iex> SHA512.hash384(<<1, 2, 3>>)
      <<134, 34, 157, 198, 210, 255, 190, 172, 115, 128, 116, 65, 84, 170, 112, 2, 145, 192, 100, 53, 42, 13, 189, 199, 123, 158, 211, 242, 200, 225, 218, 196, 220, 50, 88, 103, 211, 157, 223, 241, 210, 98, 155, 122, 57, 61, 71, 246>>
  """
  @spec hash384(bitstring) :: binary
  def hash384(binary) do
    {a, b, c, d, e, f, _, _} = (for <<block::1024 <- padding(binary)>>, do: <<block::1024>>)
      |> Enum.reduce({@i0, @i1, @i2, @i3, @i4, @i5, @i6, @i7}, &do_hash(&1, &2))
    <<a::64, b::64, c::64, d::64, e::64, f::64>>
  end

  defp do_hash(block, {aa, bb, cc, dd, ee, ff, gg, hh}) do
    # prepare the message schedule w
    w = (for <<a, b, c, d, e, f, g, h <- block>>, do: (a <<< 56) + (b <<< 48) + (c <<< 40) + (d <<< 32) + (e <<< 24) + (f <<< 16) + (g <<< 8) + h)
      |> Enum.with_index()
      |> Map.new(fn {v, k} -> {k, v} end)

    w = Enum.reduce(16..79, w, fn i, w ->
      v = (ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) + w[i - 16]) &&& @word
      Map.put(w, i, v)
    end)

    # perform the main hash computation
    {a, b, c, d, e, f, g, h} = Enum.reduce(0..79, {aa, bb, cc, dd, ee, ff, gg, hh}, fn i, {a, b, c, d, e, f, g, h} ->
      t1 = (h + bsig1(e) + ch(e, f, g) + k(i) + w[i]) &&& @word
      t2 = (bsig0(a) + maj(a, b, c)) &&& @word
      h = g
      g = f
      f = e
      e = (d + t1) &&& @word
      d = c
      c = b
      b = a
      a = (t1 + t2) &&& @word
      {a, b, c, d, e, f, g, h}
    end)

    # compute the intermediate hash value
    a = (a + aa) &&& @word
    b = (b + bb) &&& @word
    c = (c + cc) &&& @word
    d = (d + dd) &&& @word
    e = (e + ee) &&& @word
    f = (f + ff) &&& @word
    g = (g + gg) &&& @word
    h = (h + hh) &&& @word

    {a, b, c, d, e, f, g, h}
  end

  defp padding(binary) do
    len = bit_size(binary)
    p = 896 - rem(len + 1, 1024)
    n = if p >= 0, do: p, else: p + 1024
    <<binary::bits, 1::1, 0::size(n), len::128>>
  end

  # logical functions
  defp ch(x, y, z), do: (x &&& y) ^^^ (~~~x &&& z)
  defp maj(x, y, z), do: (x &&& y) ^^^ (x &&& z) ^^^ (y &&& z)
  defp bsig0(x), do: brr(x, 28) ^^^ brr(x, 34) ^^^ brr(x, 39)
  defp bsig1(x), do: brr(x, 14) ^^^ brr(x, 18) ^^^ brr(x, 41)
  defp ssig0(x), do: brr(x, 01) ^^^ brr(x, 08) ^^^ bsr(x, 07)
  defp ssig1(x), do: brr(x, 19) ^^^ brr(x, 61) ^^^ bsr(x, 06)

  # constant words
  defp k(00), do: 0x428a2f98d728ae22
  defp k(01), do: 0x7137449123ef65cd
  defp k(02), do: 0xb5c0fbcfec4d3b2f
  defp k(03), do: 0xe9b5dba58189dbbc
  defp k(04), do: 0x3956c25bf348b538
  defp k(05), do: 0x59f111f1b605d019
  defp k(06), do: 0x923f82a4af194f9b
  defp k(07), do: 0xab1c5ed5da6d8118
  defp k(08), do: 0xd807aa98a3030242
  defp k(09), do: 0x12835b0145706fbe
  defp k(10), do: 0x243185be4ee4b28c
  defp k(11), do: 0x550c7dc3d5ffb4e2
  defp k(12), do: 0x72be5d74f27b896f
  defp k(13), do: 0x80deb1fe3b1696b1
  defp k(14), do: 0x9bdc06a725c71235
  defp k(15), do: 0xc19bf174cf692694
  defp k(16), do: 0xe49b69c19ef14ad2
  defp k(17), do: 0xefbe4786384f25e3
  defp k(18), do: 0x0fc19dc68b8cd5b5
  defp k(19), do: 0x240ca1cc77ac9c65
  defp k(20), do: 0x2de92c6f592b0275
  defp k(21), do: 0x4a7484aa6ea6e483
  defp k(22), do: 0x5cb0a9dcbd41fbd4
  defp k(23), do: 0x76f988da831153b5
  defp k(24), do: 0x983e5152ee66dfab
  defp k(25), do: 0xa831c66d2db43210
  defp k(26), do: 0xb00327c898fb213f
  defp k(27), do: 0xbf597fc7beef0ee4
  defp k(28), do: 0xc6e00bf33da88fc2
  defp k(29), do: 0xd5a79147930aa725
  defp k(30), do: 0x06ca6351e003826f
  defp k(31), do: 0x142929670a0e6e70
  defp k(32), do: 0x27b70a8546d22ffc
  defp k(33), do: 0x2e1b21385c26c926
  defp k(34), do: 0x4d2c6dfc5ac42aed
  defp k(35), do: 0x53380d139d95b3df
  defp k(36), do: 0x650a73548baf63de
  defp k(37), do: 0x766a0abb3c77b2a8
  defp k(38), do: 0x81c2c92e47edaee6
  defp k(39), do: 0x92722c851482353b
  defp k(40), do: 0xa2bfe8a14cf10364
  defp k(41), do: 0xa81a664bbc423001
  defp k(42), do: 0xc24b8b70d0f89791
  defp k(43), do: 0xc76c51a30654be30
  defp k(44), do: 0xd192e819d6ef5218
  defp k(45), do: 0xd69906245565a910
  defp k(46), do: 0xf40e35855771202a
  defp k(47), do: 0x106aa07032bbd1b8
  defp k(48), do: 0x19a4c116b8d2d0c8
  defp k(49), do: 0x1e376c085141ab53
  defp k(50), do: 0x2748774cdf8eeb99
  defp k(51), do: 0x34b0bcb5e19b48a8
  defp k(52), do: 0x391c0cb3c5c95a63
  defp k(53), do: 0x4ed8aa4ae3418acb
  defp k(54), do: 0x5b9cca4f7763e373
  defp k(55), do: 0x682e6ff3d6b2b8a3
  defp k(56), do: 0x748f82ee5defb2fc
  defp k(57), do: 0x78a5636f43172f60
  defp k(58), do: 0x84c87814a1f0ab72
  defp k(59), do: 0x8cc702081a6439ec
  defp k(60), do: 0x90befffa23631e28
  defp k(61), do: 0xa4506cebde82bde9
  defp k(62), do: 0xbef9a3f7b2c67915
  defp k(63), do: 0xc67178f2e372532b
  defp k(64), do: 0xca273eceea26619c
  defp k(65), do: 0xd186b8c721c0c207
  defp k(66), do: 0xeada7dd6cde0eb1e
  defp k(67), do: 0xf57d4f7fee6ed178
  defp k(68), do: 0x06f067aa72176fba
  defp k(69), do: 0x0a637dc5a2c898a6
  defp k(70), do: 0x113f9804bef90dae
  defp k(71), do: 0x1b710b35131c471b
  defp k(72), do: 0x28db77f523047d84
  defp k(73), do: 0x32caab7b40c72493
  defp k(74), do: 0x3c9ebe0a15c9bebc
  defp k(75), do: 0x431d67c49c100d4c
  defp k(76), do: 0x4cc5d4becb3e42b6
  defp k(77), do: 0x597f299cfc657e2a
  defp k(78), do: 0x5fcb6fab3ad6faec
  defp k(79), do: 0x6c44198c4a475817

  # Binary Rotate right
  defp brr(num, n) do
    ((num >>> n) ||| (num <<< (64 - n))) &&& @word
  end
end
