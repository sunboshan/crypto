defmodule CipherTest do
  use ExUnit.Case
  alias Crypto.BlockCipher.Cipher
  doctest Cipher

  test "wrong key size" do
    assert_raise ArgumentError, fn ->
      Cipher.encrypt(:aes_ecb, "wrong_key_size", "1234567890abcdef")
    end
  end

  test "encrypt random in aes_ecb mode" do
    for _ <- 1..100 do
      key = random(Enum.random([16, 24, 32]))
      rand = random(16 * :rand.uniform(20))
      assert Cipher.encrypt(:aes_ecb, key, rand) == :crypto.block_encrypt(:aes_ecb, key, rand)
    end
  end

  test "decrypt random in aes_ecb mode" do
    for _ <- 1..100 do
      key = random(Enum.random([16, 24, 32]))
      rand = random(16 * :rand.uniform(20))
      assert Cipher.decrypt(:aes_ecb, key, Cipher.encrypt(:aes_ecb, key, rand)) == rand
    end
  end

  test "encrypt random in des_ecb mode" do
    for _ <- 1..100 do
      key = random(8)
      rand = random(8 * :rand.uniform(20))
      assert Cipher.encrypt(:des_ecb, key, rand) == :crypto.block_encrypt(:des_ecb, key, rand)
    end
  end

  test "decrypt random in des_ecb mode" do
    for _ <- 1..100 do
      key = random(8)
      rand = random(8 * :rand.uniform(20))
      assert Cipher.decrypt(:des_ecb, key, Cipher.encrypt(:des_ecb, key, rand)) == rand
    end
  end

  test "encrypt random in aes_cbc mode" do
    for _ <- 1..100 do
      key = random(Enum.random([16, 24, 32]))
      iv = random(16)
      rand = random(16 * :rand.uniform(20))
      assert Cipher.encrypt(:aes_cbc, key, iv, rand) == :crypto.block_encrypt(:aes_cbc, key, iv, rand)
    end
  end

  test "decrypt random in aes_cbc mode" do
    for _ <- 1..100 do
      key = random(Enum.random([16, 24, 32]))
      iv = random(16)
      rand = random(16 * :rand.uniform(20))
      assert Cipher.decrypt(:aes_cbc, key, iv, Cipher.encrypt(:aes_cbc, key, iv, rand)) == rand
    end
  end

  test "encrypt random in des_cbc mode" do
    for _ <- 1..100 do
      key = random(8)
      iv = random(8)
      rand = random(8 * :rand.uniform(20))
      assert Cipher.encrypt(:des_cbc, key, iv, rand) == :crypto.block_encrypt(:des_cbc, key, iv, rand)
    end
  end

  test "decrypt random in des_cbc mode" do
    for _ <- 1..100 do
      key = random(8)
      iv = random(8)
      rand = random(8 * :rand.uniform(20))
      assert Cipher.decrypt(:des_cbc, key, iv, Cipher.encrypt(:des_cbc, key, iv, rand)) == rand
    end
  end

  test "encrypt random in aes_cfb mode for 128-bits key" do
    # there's a bug in Erlang OTP 19 that cause aes_cfb128
    # wrongly using aes_cfb8 when key size is 192/256-bits
    # https://bugs.erlang.org/browse/ERL-328
    for _ <- 1..100 do
      key = random(16)
      iv = random(16)
      rand = random(:rand.uniform(200))
      assert Cipher.encrypt(:aes_cfb, key, iv, rand) == :crypto.block_encrypt(:aes_cfb128, key, iv, rand)
    end
  end

  test "encrypt in aes_cfb modea for 192/256-bits key" do
    # openssl cmd for using aes_cfb
    # echo -n 123 | openssl enc -aes-192-cfb -K 815a765384a501737d035ac21a066659f8061059663e19d9 -iv 9d34a99f1e5d184d3777f639ae98fd49 -a
    key_192 = <<0x815a765384a501737d035ac21a066659f8061059663e19d9::192>>
    key_256 = <<0x857c4822e8b33cf6c3bb3fd34d63f90a9c4288919769b4197311c2f68384109b::256>>
    iv = <<0x9d34a99f1e5d184d3777f639ae98fd49::128>>
    assert Cipher.encrypt(:aes_cfb, key_192, iv, "你好世界！") == <<180, 172, 2, 73, 244, 165, 19, 250, 47, 179, 109, 171, 72, 119, 74>>
    assert Cipher.encrypt(:aes_cfb, key_192, iv, "hello world!") == <<56, 116, 206, 192, 62, 56, 128, 45, 203, 56, 156, 6>>
    assert Cipher.encrypt(:aes_cfb, key_192, iv, "🙂👻🐶") == <<160, 142, 59, 46, 161, 135, 102, 249, 73, 203, 104, 145>>
    assert Cipher.encrypt(:aes_cfb, key_256, iv, "你好世界！") == <<119, 23, 64, 216, 67, 157, 130, 94, 180, 153, 118, 45, 228, 102, 255>>
    assert Cipher.encrypt(:aes_cfb, key_256, iv, "hello world!") == <<251, 207, 140, 81, 137, 0, 17, 137, 80, 18, 135, 128>>
    assert Cipher.encrypt(:aes_cfb, key_256, iv, "🙂👻🐶") == <<99, 53, 121, 191, 22, 191, 247, 93, 210, 225, 115, 23>>
  end

  test "decrypt random in aes_cfb mode" do
    for _ <- 1..100 do
      key = random(Enum.random([16, 24, 32]))
      iv = random(16)
      rand = random(:rand.uniform(100))
      assert Cipher.decrypt(:aes_cfb, key, iv, Cipher.encrypt(:aes_cfb, key, iv, rand)) == rand
    end
  end

  test "encrypt random in aes_ofb mode" do
    key = <<0x31323334353637383930616263646566::128>>
    iv = <<0x339da91f6d88021b33a50e04eea87d63::128>>
    assert Cipher.encrypt(:aes_ofb, key, iv, "你好世界！") == <<17, 250, 165, 250, 136, 17, 75, 34, 14, 56, 65, 243, 202, 190, 83>>
    assert Cipher.encrypt(:aes_ofb, key, iv, "hello world!") == <<157, 34, 105, 115, 66, 140, 216, 245, 234, 179, 176, 94>>
    assert Cipher.encrypt(:aes_ofb, key, iv, "🙂👻🐶") == <<5, 216, 156, 157, 221, 51, 62, 33, 104, 64, 68, 201>>
  end

  test "decrypt random in aes_ofb mode" do
    for _ <- 1..100 do
      key = random(Enum.random([16, 24, 32]))
      iv = random(16)
      rand = random(:rand.uniform(100))
      assert Cipher.decrypt(:aes_ofb, key, iv, Cipher.encrypt(:aes_ofb, key, iv, rand)) == rand
    end
  end

  defp random(n) do
    for _ <- 1..n, into: <<>>, do: <<:rand.uniform(0xff)>>
  end
end
