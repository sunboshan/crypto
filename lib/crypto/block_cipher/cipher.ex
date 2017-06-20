defmodule Crypto.BlockCipher.Cipher do
  @moduledoc """
  Implement `ECB/CBC/CFB/OFB` block cipher modes according to NIST SP 800-38A.
  """

  import Bitwise

  alias Crypto.BlockCipher.AES
  alias Crypto.BlockCipher.DES

  @doc """
  Encryption for ecb mode.
  """
  def encrypt(:aes_ecb, key, binary) when rem(bit_size(binary), 128) == 0 do
    ecb(key, binary, {AES, :encrypt, 128})
  end
  def encrypt(:des_ecb, key, binary) when rem(bit_size(binary), 64) == 0 do
    ecb(key, binary, {DES, :encrypt, 64})
  end
  def encrypt(_, _, _), do: raise ArgumentError

  @doc """
  Decryption for ecb mode.
  """
  def decrypt(:aes_ecb, key, binary) when rem(bit_size(binary), 128) == 0 do
    ecb(key, binary, {AES, :decrypt, 128})
  end
  def decrypt(:des_ecb, key, binary) when rem(bit_size(binary), 64) == 0 do
    ecb(key, binary, {DES, :decrypt, 64})
  end
  def decrypt(_, _, _), do: raise ArgumentError

  @doc """
  Encryption for cbc/cfb/ofb/ctr mode.
  """
  def encrypt(:aes_cbc, key, iv, binary) when bit_size(iv) == 128 and rem(bit_size(binary), 128) == 0 do
    cbc(key, iv, binary, {AES, :enc, 128})
  end
  def encrypt(:des_cbc, key, iv, binary) when bit_size(iv) == 64 and rem(bit_size(binary), 64) == 0 do
    cbc(key, iv, binary, {DES, :enc, 64})
  end
  def encrypt(:aes_cfb, key, iv, binary) when bit_size(iv) == 128 do
    cfb(:enc, key, iv, binary, <<>>)
  end
  def encrypt(:aes_ofb, key, iv, binary) when bit_size(iv) == 128 do
    ofb(key, iv, binary, <<>>)
  end
  def encrypt(:aes_ctr, key, iv, binary) when bit_size(iv) == 128 do
    ctr(key, iv, binary, <<>>)
  end
  def encrypt(_, _, _, _), do: raise ArgumentError

  @doc """
  Decryption for cbc/cfb/ofb/ctr mode.
  """
  def decrypt(:aes_cbc, key, iv, binary) when bit_size(iv) == 128 and rem(bit_size(binary), 128) == 0 do
    cbc(key, iv, binary, {AES, :dec, 128})
  end
  def decrypt(:des_cbc, key, iv, binary) when bit_size(iv) == 64 and rem(bit_size(binary), 64) == 0 do
    cbc(key, iv, binary, {DES, :dec, 64})
  end
  def decrypt(:aes_cfb, key, iv, binary) when bit_size(iv) == 128 do
    cfb(:dec, key, iv, binary, <<>>)
  end
  def decrypt(:aes_ofb, key, iv, binary) when bit_size(iv) == 128 do
    ofb(key, iv, binary, <<>>)
  end
  def decrypt(:aes_ctr, key, iv, binary) when bit_size(iv) == 128 do
    ctr(key, iv, binary, <<>>)
  end
  def decrypt(_, _, _, _), do: raise ArgumentError

  @doc """
  Padding scheme defined in PKCS#7.
  """
  def padding(block, size) do
    n = case rem(byte_size(block), size) do
      0 -> size
      n -> size - n
    end
    padding = for _ <- 1..n, into: <<>>, do: <<n>>
    <<block::binary, padding::binary>>
  end

  @doc """
  Unpadding for PKCS#7 padded binary.
  """
  def unpadding(block) do
    block_size = byte_size(block)
    size = block_size - 1
    <<_::binary-size(size), n>> = block
    size = block_size - n
    <<unpadded::binary-size(size), _::binary>> = block
    unpadded
  end

  defp ecb(key, binary, {mod, fun, size}) do
    for <<block::size(size) <- binary>>, into: <<>> do
      apply(mod, fun, [key, <<block::size(size)>>])
    end
  end

  defp cbc(key, iv, binary, {mod, :enc, size}) do
    (for <<block::size(size) <- binary>>, do: <<block::size(size)>>)
    |> Enum.reduce({iv, <<>>}, fn <<plain::size(size)>>, {<<cipher::size(size)>>, acc} ->
      c = apply(mod, :encrypt, [key, <<(plain ^^^ cipher)::size(size)>>])
      {c, acc <> c}
    end)
    |> elem(1)
  end
  defp cbc(key, iv, binary, {mod, :dec, size}) do
    (for <<block::size(size) <- binary>>, do: <<block::size(size)>>)
    |> Enum.reduce({iv, <<>>}, fn cipher, {<<c::size(size)>>, acc} ->
      <<p::size(size)>> = apply(mod, :decrypt, [key, cipher])
      plain = <<(p ^^^ c)::size(size)>>
      {cipher, acc <> plain}
    end)
    |> elem(1)
  end

  defp cfb(:enc, key, iv, <<p::128, t::binary>>, acc) do
    <<o::128>> = AES.encrypt(key, iv)
    c = <<(p ^^^ o)::128>>
    cfb(:enc, key, c, t, acc <> c)
  end
  defp cfb(:enc, key, iv, plain, acc) do
    size = bit_size(plain)
    <<o::size(size), _::binary>> = AES.encrypt(key, iv)
    <<p::size(size)>> = plain
    c = <<(p ^^^ o)::size(size)>>
    acc <> c
  end

  defp cfb(:dec, key, iv, <<c::128, t::binary>>, acc) do
    <<o::128>> = AES.encrypt(key, iv)
    p = <<(c ^^^ o)::128>>
    cfb(:dec, key, <<c::128>>, t, acc <> p)
  end
  defp cfb(:dec, key, iv, cipher, acc) do
    size = bit_size(cipher)
    <<o::size(size), _::binary>> = AES.encrypt(key, iv)
    <<c::size(size)>> = cipher
    p = <<(c ^^^ o)::size(size)>>
    acc <> p
  end

  defp ofb(key, iv, <<p::128, t::binary>>, acc) do
    <<o::128>> = new_iv = AES.encrypt(key, iv)
    c = <<(p ^^^ o)::128>>
    ofb(key, new_iv, t, acc <> c)
  end
  defp ofb(key, iv, plain, acc) do
    size = bit_size(plain)
    <<o::size(size), _::binary>> = AES.encrypt(key, iv)
    <<p::size(size)>> = plain
    c = <<(p ^^^ o)::size(size)>>
    acc <> c
  end

  defp ctr(key, <<n::128>> = iv, <<p::128, t::binary>>, acc) do
    <<o::128>> = AES.encrypt(key, iv)
    c = <<(p ^^^ o)::128>>
    ctr(key, <<(n + 1)::128>>, t, acc <> c)
  end
  defp ctr(key, iv, plain, acc) do
    size = bit_size(plain)
    <<o::size(size), _::binary>> = AES.encrypt(key, iv)
    <<p::size(size)>> = plain
    c = <<(p ^^^ o)::size(size)>>
    acc <> c
  end
end
