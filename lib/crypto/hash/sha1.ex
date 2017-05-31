defmodule Crypto.Hash.SHA1 do
  @moduledoc """
  Implement SHA1 hash function according to RFC 3174.
  """

  import Bitwise

  @h0 0x67452301
  @h1 0xEFCDAB89
  @h2 0x98BADCFE
  @h3 0x10325476
  @h4 0xC3D2E1F0

  @doc """
  Calculate SHA1 hash value for a given bitstring.

  Example:

      iex> SHA1.hash("abc")
      <<169, 153, 62, 54, 71, 6, 129, 106, 186, 62, 37, 113, 120, 80, 194, 108, 156, 208, 216, 157>>
      iex> SHA1.hash(<<1, 2, 3>>)
      <<112, 55, 128, 113, 152, 194, 42, 125, 43, 8, 7, 55, 29, 118, 55, 121, 168, 79, 223, 207>>
  """
  @spec hash(bitstring) :: <<_::160>>
  def hash(binary) do
    {a, b, c, d, e} = (for <<block::512 <- padding(binary)>>, do: <<block::512>>)
      |> Enum.reduce({@h0, @h1, @h2, @h3, @h4}, &do_hash(&1, &2))
    <<a::32, b::32, c::32, d::32, e::32>>
  end

  defp do_hash(block, {aa, bb, cc, dd, ee}) do
    # calculate w[0]..w[15]
    w = (for <<a, b, c, d <- block>>, do: (a <<< 24) + (b <<< 16) + (c <<< 8) + d)
      |> Enum.with_index()
      |> Map.new(fn {v, k} -> {k, v} end)

    # calculate w[16]..w[79]
    w = Enum.reduce(16..79, w, fn i, w ->
      Map.put(w, i, brl(w[i - 3] ^^^ w[i - 8] ^^^ w[i - 14] ^^^ w[i - 16], 1))
    end)

    # 80 steps to calculate digest
    {a, b, c, d, e} = Enum.reduce(0..79, {aa, bb, cc, dd, ee}, fn i, {a, b, c, d, e} ->
      temp = (brl(a, 5) + f(i, {b, c, d}) + e + w[i] + k(i)) &&& 0xffffffff
      e = d
      d = c
      c = brl(b, 30)
      b = a
      a = temp
      {a, b, c, d, e}
    end)

    # add initial value
    a = (a + aa) &&& 0xffffffff
    b = (b + bb) &&& 0xffffffff
    c = (c + cc) &&& 0xffffffff
    d = (d + dd) &&& 0xffffffff
    e = (e + ee) &&& 0xffffffff

    {a, b, c, d, e}
  end

  defp padding(binary) do
    len = bit_size(binary)
    p = 448 - rem(len + 1, 512)
    n = if p >= 0, do: p, else: p + 512
    <<binary::bits, 1::1, 0::size(n), len::64>>
  end

  defp f(t, {b, c, d}) when t in 00..19, do: (b &&& c) ||| (~~~b &&& d)
  defp f(t, {b, c, d}) when t in 20..39, do: b ^^^ c ^^^ d
  defp f(t, {b, c, d}) when t in 40..59, do: (b &&& c) ||| (b &&& d) ||| (c &&& d)
  defp f(t, {b, c, d}) when t in 60..79, do: b ^^^ c ^^^ d

  defp k(t) when t in 00..19, do: 0x5A827999
  defp k(t) when t in 20..39, do: 0x6ED9EBA1
  defp k(t) when t in 40..59, do: 0x8F1BBCDC
  defp k(t) when t in 60..79, do: 0xCA62C1D6

  # Binary Rotate Left
  defp brl(num, n) do
    ((num <<< n) ||| (num >>> (32 - n))) &&& 0xffffffff
  end
end
