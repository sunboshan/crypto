defmodule AESTest do
  use ExUnit.Case
  alias Crypto.BlockCipher.AES
  doctest AES

  test "encrypt random with 128-bits key" do
    for _ <- 1..1000 do
      key = random(16)
      rand = random(16)
      assert AES.encrypt(key, rand) == :crypto.block_encrypt(:aes_ecb, key, rand)
    end
  end

  test "encrypt random with 192-bits key" do
    for _ <- 1..1000 do
      key = random(24)
      rand = random(16)
      assert AES.encrypt(key, rand) == :crypto.block_encrypt(:aes_ecb, key, rand)
    end
  end

  test "encrypt random with 256-bits key" do
    for _ <- 1..1000 do
      key = random(32)
      rand = random(16)
      assert AES.encrypt(key, rand) == :crypto.block_encrypt(:aes_ecb, key, rand)
    end
  end

  test "decrypt random with 128-bits key" do
    for _ <- 1..1000 do
      key = random(16)
      rand = random(16)
      assert AES.decrypt(key, AES.encrypt(key, rand)) == rand
    end
  end

  test "decrypt random with 192-bits key" do
    for _ <- 1..1000 do
      key = random(24)
      rand = random(16)
      assert AES.decrypt(key, AES.encrypt(key, rand)) == rand
    end
  end

  test "decrypt random with 256-bits key" do
    for _ <- 1..1000 do
      key = random(32)
      rand = random(16)
      assert AES.decrypt(key, AES.encrypt(key, rand)) == rand
    end
  end

  defp random(n) do
    for _ <- 1..n, into: <<>>, do: <<:rand.uniform(0xff)>>
  end
end
