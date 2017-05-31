defmodule AESTest do
  use ExUnit.Case
  alias Crypto.BlockCipher.AES
  doctest AES

  test "encrypt random" do
    for _ <- 1..1000 do
      key = random()
      rand = random()
      assert AES.encrypt(key, rand) == :crypto.block_encrypt(:aes_ecb, key, rand)
    end
  end

  defp random do
    for _ <- 1..16, into: <<>>, do: <<:rand.uniform(0xff)>>
  end
end
