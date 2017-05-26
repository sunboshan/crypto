defmodule Crypto.Hash.SHA256 do
  @moduledoc """
  Implement SHA224/256 hash function according to RFC 6234.
  """

  import Bitwise

  # SHA256 initial hash
  @h0 0x6a09e667
  @h1 0xbb67ae85
  @h2 0x3c6ef372
  @h3 0xa54ff53a
  @h4 0x510e527f
  @h5 0x9b05688c
  @h6 0x1f83d9ab
  @h7 0x5be0cd19

  # SHA224 initial hash
  @i0 0xc1059ed8
  @i1 0x367cd507
  @i2 0x3070dd17
  @i3 0xf70e5939
  @i4 0xffc00b31
  @i5 0x68581511
  @i6 0x64f98fa7
  @i7 0xbefa4fa4

  @doc """
  Calculate SHA256 hash value for a given bitstring.

  Example:

      iex> SHA256.hash("abc")
      <<186, 120, 22, 191, 143, 1, 207, 234, 65, 65, 64, 222, 93, 174, 34, 35, 176, 3, 97, 163, 150, 23, 122, 156, 180, 16, 255, 97, 242, 0, 21, 173>>
      iex> SHA256.hash(<<1, 2, 3>>)
      <<3, 144, 88, 198, 242, 192, 203, 73, 44, 83, 59, 10, 77, 20, 239, 119, 204, 15, 120, 171, 204, 206, 213, 40, 125, 132, 161, 162, 1, 28, 251, 129>>
  """
  @spec hash(bitstring) :: binary
  def hash(binary) do
    {a, b, c, d, e, f, g, h} = (for <<block::512 <- padding(binary)>>, do: <<block::512>>)
      |> Enum.reduce({@h0, @h1, @h2, @h3, @h4, @h5, @h6, @h7}, &do_hash(&1, &2))
    <<a::32, b::32, c::32, d::32, e::32, f::32, g::32, h::32>>
  end

  @doc """
  Calculate SHA224 hash value for a given bitstring.

  Example:

      iex> SHA256.hash224("abc")
      <<35, 9, 125, 34, 52, 5, 216, 34, 134, 66, 164, 119, 189, 162, 85, 179, 42, 173, 188, 228, 189, 160, 179, 247, 227, 108, 157, 167>>
      iex> SHA256.hash224(<<1, 2, 3>>)
      <<57, 23, 170, 170, 166, 29, 129, 222, 185, 62, 241, 194, 126, 198, 71, 241, 38, 251, 147, 40, 148, 183, 202, 169, 223, 40, 97, 147>>
  """
  @spec hash224(bitstring) :: binary
  def hash224(binary) do
    {a, b, c, d, e, f, g, _} = (for <<block::512 <- padding(binary)>>, do: <<block::512>>)
      |> Enum.reduce({@i0, @i1, @i2, @i3, @i4, @i5, @i6, @i7}, &do_hash(&1, &2))
    <<a::32, b::32, c::32, d::32, e::32, f::32, g::32>>
  end

  defp do_hash(block, {aa, bb, cc, dd, ee, ff, gg, hh}) do
    # prepare the message schedule w
    w = (for <<a, b, c, d <- block>>, do: (a <<< 24) + (b <<< 16) + (c <<< 8) + d)
      |> Enum.with_index()
      |> Map.new(fn {v, k} -> {k, v} end)

    w = Enum.reduce(16..63, w, fn i, w ->
      v = (ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) + w[i - 16]) &&& 0xffffffff
      Map.put(w, i, v)
    end)

    # perform the main hash computation
    {a, b, c, d, e, f, g, h} = Enum.reduce(0..63, {aa, bb, cc, dd, ee, ff, gg, hh}, fn i, {a, b, c, d, e, f, g, h} ->
      t1 = (h + bsig1(e) + ch(e, f, g) + k(i) + w[i]) &&& 0xffffffff
      t2 = (bsig0(a) + maj(a, b, c)) &&& 0xffffffff
      h = g
      g = f
      f = e
      e = (d + t1) &&& 0xffffffff
      d = c
      c = b
      b = a
      a = (t1 + t2) &&& 0xffffffff
      {a, b, c, d, e, f, g, h}
    end)

    # compute the intermediate hash value
    a = (a + aa) &&& 0xffffffff
    b = (b + bb) &&& 0xffffffff
    c = (c + cc) &&& 0xffffffff
    d = (d + dd) &&& 0xffffffff
    e = (e + ee) &&& 0xffffffff
    f = (f + ff) &&& 0xffffffff
    g = (g + gg) &&& 0xffffffff
    h = (h + hh) &&& 0xffffffff

    {a, b, c, d, e, f, g, h}
  end

  defp padding(binary) do
    len = bit_size(binary)
    p = 448 - rem(len + 1, 512)
    n = if p >= 0, do: p, else: p + 512
    <<binary::bits, 1::1, 0::size(n), len::64>>
  end

  # logical functions
  defp ch(x, y, z), do: (x &&& y) ^^^ (~~~x &&& z)
  defp maj(x, y, z), do: (x &&& y) ^^^ (x &&& z) ^^^ (y &&& z)
  defp bsig0(x), do: brr(x, 02) ^^^ brr(x, 13) ^^^ brr(x, 22)
  defp bsig1(x), do: brr(x, 06) ^^^ brr(x, 11) ^^^ brr(x, 25)
  defp ssig0(x), do: brr(x, 07) ^^^ brr(x, 18) ^^^ bsr(x, 03)
  defp ssig1(x), do: brr(x, 17) ^^^ brr(x, 19) ^^^ bsr(x, 10)

  # constant words
  defp k(00), do: 0x428a2f98
  defp k(01), do: 0x71374491
  defp k(02), do: 0xb5c0fbcf
  defp k(03), do: 0xe9b5dba5
  defp k(04), do: 0x3956c25b
  defp k(05), do: 0x59f111f1
  defp k(06), do: 0x923f82a4
  defp k(07), do: 0xab1c5ed5
  defp k(08), do: 0xd807aa98
  defp k(09), do: 0x12835b01
  defp k(10), do: 0x243185be
  defp k(11), do: 0x550c7dc3
  defp k(12), do: 0x72be5d74
  defp k(13), do: 0x80deb1fe
  defp k(14), do: 0x9bdc06a7
  defp k(15), do: 0xc19bf174
  defp k(16), do: 0xe49b69c1
  defp k(17), do: 0xefbe4786
  defp k(18), do: 0x0fc19dc6
  defp k(19), do: 0x240ca1cc
  defp k(20), do: 0x2de92c6f
  defp k(21), do: 0x4a7484aa
  defp k(22), do: 0x5cb0a9dc
  defp k(23), do: 0x76f988da
  defp k(24), do: 0x983e5152
  defp k(25), do: 0xa831c66d
  defp k(26), do: 0xb00327c8
  defp k(27), do: 0xbf597fc7
  defp k(28), do: 0xc6e00bf3
  defp k(29), do: 0xd5a79147
  defp k(30), do: 0x06ca6351
  defp k(31), do: 0x14292967
  defp k(32), do: 0x27b70a85
  defp k(33), do: 0x2e1b2138
  defp k(34), do: 0x4d2c6dfc
  defp k(35), do: 0x53380d13
  defp k(36), do: 0x650a7354
  defp k(37), do: 0x766a0abb
  defp k(38), do: 0x81c2c92e
  defp k(39), do: 0x92722c85
  defp k(40), do: 0xa2bfe8a1
  defp k(41), do: 0xa81a664b
  defp k(42), do: 0xc24b8b70
  defp k(43), do: 0xc76c51a3
  defp k(44), do: 0xd192e819
  defp k(45), do: 0xd6990624
  defp k(46), do: 0xf40e3585
  defp k(47), do: 0x106aa070
  defp k(48), do: 0x19a4c116
  defp k(49), do: 0x1e376c08
  defp k(50), do: 0x2748774c
  defp k(51), do: 0x34b0bcb5
  defp k(52), do: 0x391c0cb3
  defp k(53), do: 0x4ed8aa4a
  defp k(54), do: 0x5b9cca4f
  defp k(55), do: 0x682e6ff3
  defp k(56), do: 0x748f82ee
  defp k(57), do: 0x78a5636f
  defp k(58), do: 0x84c87814
  defp k(59), do: 0x8cc70208
  defp k(60), do: 0x90befffa
  defp k(61), do: 0xa4506ceb
  defp k(62), do: 0xbef9a3f7
  defp k(63), do: 0xc67178f2

  # Binary Rotate right
  defp brr(num, n) do
    ((num >>> n) ||| (num <<< (32 - n))) &&& 0xffffffff
  end
end
