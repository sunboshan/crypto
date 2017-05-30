defmodule DESTest do
  use ExUnit.Case
  alias Crypto.BlockCipher.DES
  doctest DES

  test "encrypt random" do
    for _ <- 1..1000 do
      key = random()
      rand = random()
      assert DES.encrypt(key, rand) == :crypto.block_encrypt(:des_ecb, key, rand)
    end
  end

  test "decrypt random" do
    for _ <- 1..1000 do
      key = random()
      rand = random()
      assert DES.decrypt(key, DES.encrypt(key, rand)) == rand
    end
  end

  defp random do
    for _ <- 1..8, into: <<>>, do: <<:rand.uniform(0xff)>>
  end
end
