defmodule MD5 do
  @moduledoc """
  Implement MD5 hash function according to RFC 1321.
  """

  import Bitwise

  @aa 0x67452301
  @bb 0xefcdab89
  @cc 0x98badcfe
  @dd 0x10325476

  @doc """
  Calculate MD5 hash value for a given bitstring.

  Example:

      iex> MD5.hash("abc")
      <<144, 1, 80, 152, 60, 210, 79, 176, 214, 150, 63, 125, 40, 225, 127, 114>>
      iex> MD5.hash(<<1, 2, 3>>)
      <<82, 137, 223, 115, 125, 245, 115, 38, 252, 221, 34, 89, 122, 251, 31, 172>>
  """
  @spec hash(bitstring) :: binary
  def hash(binary) do
    {a, b, c, d} = (for <<block::512 <- padding(binary)>>, do: <<block::512>>)
      |> Enum.reduce({@aa, @bb, @cc, @dd}, &do_hash(&1, &2))
    <<a::little-32, b::little-32, c::little-32, d::little-32>>
  end

  defp do_hash(block, {aa, bb, cc, dd}) do
    x = (for <<a, b, c, d <- block>>, do: a + (b <<< 8) + (c <<< 16) + (d <<< 24))
      |> Enum.with_index()
      |> Map.new(fn {v, k} -> {k, v} end)

    {a, b, c, d} = {aa, bb, cc, dd}

    # round 1
    a = ff(a, b, c, d, x[00], 07, 0xd76aa478)
    d = ff(d, a, b, c, x[01], 12, 0xe8c7b756)
    c = ff(c, d, a, b, x[02], 17, 0x242070db)
    b = ff(b, c, d, a, x[03], 22, 0xc1bdceee)
    a = ff(a, b, c, d, x[04], 07, 0xf57c0faf)
    d = ff(d, a, b, c, x[05], 12, 0x4787c62a)
    c = ff(c, d, a, b, x[06], 17, 0xa8304613)
    b = ff(b, c, d, a, x[07], 22, 0xfd469501)
    a = ff(a, b, c, d, x[08], 07, 0x698098d8)
    d = ff(d, a, b, c, x[09], 12, 0x8b44f7af)
    c = ff(c, d, a, b, x[10], 17, 0xffff5bb1)
    b = ff(b, c, d, a, x[11], 22, 0x895cd7be)
    a = ff(a, b, c, d, x[12], 07, 0x6b901122)
    d = ff(d, a, b, c, x[13], 12, 0xfd987193)
    c = ff(c, d, a, b, x[14], 17, 0xa679438e)
    b = ff(b, c, d, a, x[15], 22, 0x49b40821)

    # round 2
    a = gg(a, b, c, d, x[01], 05, 0xf61e2562)
    d = gg(d, a, b, c, x[06], 09, 0xc040b340)
    c = gg(c, d, a, b, x[11], 14, 0x265e5a51)
    b = gg(b, c, d, a, x[00], 20, 0xe9b6c7aa)
    a = gg(a, b, c, d, x[05], 05, 0xd62f105d)
    d = gg(d, a, b, c, x[10], 09, 0x02441453)
    c = gg(c, d, a, b, x[15], 14, 0xd8a1e681)
    b = gg(b, c, d, a, x[04], 20, 0xe7d3fbc8)
    a = gg(a, b, c, d, x[09], 05, 0x21e1cde6)
    d = gg(d, a, b, c, x[14], 09, 0xc33707d6)
    c = gg(c, d, a, b, x[03], 14, 0xf4d50d87)
    b = gg(b, c, d, a, x[08], 20, 0x455a14ed)
    a = gg(a, b, c, d, x[13], 05, 0xa9e3e905)
    d = gg(d, a, b, c, x[02], 09, 0xfcefa3f8)
    c = gg(c, d, a, b, x[07], 14, 0x676f02d9)
    b = gg(b, c, d, a, x[12], 20, 0x8d2a4c8a)

    # round 3
    a = hh(a, b, c, d, x[05], 04, 0xfffa3942)
    d = hh(d, a, b, c, x[08], 11, 0x8771f681)
    c = hh(c, d, a, b, x[11], 16, 0x6d9d6122)
    b = hh(b, c, d, a, x[14], 23, 0xfde5380c)
    a = hh(a, b, c, d, x[01], 04, 0xa4beea44)
    d = hh(d, a, b, c, x[04], 11, 0x4bdecfa9)
    c = hh(c, d, a, b, x[07], 16, 0xf6bb4b60)
    b = hh(b, c, d, a, x[10], 23, 0xbebfbc70)
    a = hh(a, b, c, d, x[13], 04, 0x289b7ec6)
    d = hh(d, a, b, c, x[00], 11, 0xeaa127fa)
    c = hh(c, d, a, b, x[03], 16, 0xd4ef3085)
    b = hh(b, c, d, a, x[06], 23, 0x04881d05)
    a = hh(a, b, c, d, x[09], 04, 0xd9d4d039)
    d = hh(d, a, b, c, x[12], 11, 0xe6db99e5)
    c = hh(c, d, a, b, x[15], 16, 0x1fa27cf8)
    b = hh(b, c, d, a, x[02], 23, 0xc4ac5665)

    # round 4
    a = ii(a, b, c, d, x[00], 06, 0xf4292244)
    d = ii(d, a, b, c, x[07], 10, 0x432aff97)
    c = ii(c, d, a, b, x[14], 15, 0xab9423a7)
    b = ii(b, c, d, a, x[05], 21, 0xfc93a039)
    a = ii(a, b, c, d, x[12], 06, 0x655b59c3)
    d = ii(d, a, b, c, x[03], 10, 0x8f0ccc92)
    c = ii(c, d, a, b, x[10], 15, 0xffeff47d)
    b = ii(b, c, d, a, x[01], 21, 0x85845dd1)
    a = ii(a, b, c, d, x[08], 06, 0x6fa87e4f)
    d = ii(d, a, b, c, x[15], 10, 0xfe2ce6e0)
    c = ii(c, d, a, b, x[06], 15, 0xa3014314)
    b = ii(b, c, d, a, x[13], 21, 0x4e0811a1)
    a = ii(a, b, c, d, x[04], 06, 0xf7537e82)
    d = ii(d, a, b, c, x[11], 10, 0xbd3af235)
    c = ii(c, d, a, b, x[02], 15, 0x2ad7d2bb)
    b = ii(b, c, d, a, x[09], 21, 0xeb86d391)

    a = (a + aa) &&& 0xffffffff
    b = (b + bb) &&& 0xffffffff
    c = (c + cc) &&& 0xffffffff
    d = (d + dd) &&& 0xffffffff

    {a, b, c, d}
  end

  defp padding(binary) do
    len = bit_size(binary)
    p = 448 - rem(len + 1, 512)
    n = if p >= 0, do: p, else: p + 512
    len = len &&& 0xffffffffffffffff
    <<binary::bits, 1::1, 0::size(n), len::little-64>>
  end

  defp f(x, y, z), do: (x &&& y) ||| (~~~x &&& z)
  defp g(x, y, z), do: (x &&& z) ||| (~~~z &&& y)
  defp h(x, y, z), do: x ^^^ y ^^^ z
  defp i(x, y, z), do: y ^^^ (x ||| ~~~z)

  defp ff(a, b, c, d, xk, s, ti), do: (b + brl((a + f(b, c, d) + xk + ti), s)) &&& 0xffffffff
  defp gg(a, b, c, d, xk, s, ti), do: (b + brl((a + g(b, c, d) + xk + ti), s)) &&& 0xffffffff
  defp hh(a, b, c, d, xk, s, ti), do: (b + brl((a + h(b, c, d) + xk + ti), s)) &&& 0xffffffff
  defp ii(a, b, c, d, xk, s, ti), do: (b + brl((a + i(b, c, d) + xk + ti), s)) &&& 0xffffffff

  # Binary Rotate Left
  defp brl(num, n) do
    num = num &&& 0xffffffff
    ((num <<< n) ||| (num >>> (32 - n))) &&& 0xffffffff
  end
end
