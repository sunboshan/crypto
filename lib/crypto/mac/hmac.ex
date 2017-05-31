defmodule Crypto.MAC.HMAC do
  @moduledoc """
  Implement HMAC message authentication codes according to FIPS 198-1.
  """

  import Bitwise

  @type hash_algorithms :: :md5 | :sha1 | :sha224 | :sha256 | :sha384 | :sha512

  @doc """
  Calculate hmac value for a given key and binary.

  Example:

      iex> HMAC.hash(:sha256, "", "")
      <<182, 19, 103, 154, 8, 20, 217, 236, 119, 47, 149, 215, 120, 195, 95, 197, 255, 22, 151, 196, 147, 113, 86, 83, 198, 199, 18, 20, 66, 146, 197, 173>>
      iex> HMAC.hash(:sha512, "1234", "abcd")
      <<2, 113, 57, 33, 28, 175, 221, 207, 80, 52, 216, 22, 255, 90, 52, 145, 52, 157, 108, 122, 3, 230, 54, 98, 229, 212, 126, 47, 57, 87, 140, 122, 49, 25, 53, 218, 120, 207, 1, 13, 169, 157, 65, 26, 7, 248, 244, 219, 207, 248, 86, 26, 3, 127, 175, 3, 239, 55, 3, 244, 173, 56, 11, 153>>
  """
  @spec hash(hash_algorithms, binary, binary) :: binary
  def hash(type, key, binary) do
    # get metadata
    {mod, fun, block_size} = meta(type)

    # determine k0
    n = block_size - byte_size(key)
    <<k0::unit(8)-size(block_size)>> = if n >= 0 do
      <<key::binary, 0::unit(8)-size(n)>>
    else
      h0 = apply(mod, fun, [key])
      n = block_size - byte_size(h0)
      <<h0::binary, 0::unit(8)-size(n)>>
    end

    # construct padding
    <<ipad::unit(8)-size(block_size)>> = ipad(block_size)
    <<opad::unit(8)-size(block_size)>> = opad(block_size)

    # calculate hash
    h1 = apply(mod, fun, [<<(k0 ^^^ ipad)::unit(8)-size(block_size), binary::binary>>])
    apply(mod, fun, [<<(k0 ^^^ opad)::unit(8)-size(block_size), h1::binary>>])
  end

  defp meta(:md5),    do: {Crypto.Hash.MD5,    :hash,    64}
  defp meta(:sha1),   do: {Crypto.Hash.SHA1,   :hash,    64}
  defp meta(:sha224), do: {Crypto.Hash.SHA256, :hash224, 64}
  defp meta(:sha256), do: {Crypto.Hash.SHA256, :hash,    64}
  defp meta(:sha384), do: {Crypto.Hash.SHA512, :hash384, 128}
  defp meta(:sha512), do: {Crypto.Hash.SHA512, :hash,    128}

  defp ipad(size), do: for _ <- 1..size, into: <<>>, do: <<0x36>>
  defp opad(size), do: for _ <- 1..size, into: <<>>, do: <<0x5c>>
end
