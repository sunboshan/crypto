defmodule HMACTest do
  use ExUnit.Case
  alias Crypto.MAC.HMAC
  doctest HMAC

  test "md5 random" do
    for _ <- 1..100 do
      key = random()
      rand = random()
      assert HMAC.hash(:md5, key, rand) == :crypto.hmac(:md5, key, rand)
    end
  end

  test "sha1 random" do
    for _ <- 1..100 do
      key = random()
      rand = random()
      assert HMAC.hash(:sha1, key, rand) == :crypto.hmac(:sha, key, rand)
    end
  end

  test "sha224 random" do
    for _ <- 1..100 do
      key = random()
      rand = random()
      assert HMAC.hash(:sha224, key, rand) == :crypto.hmac(:sha224, key, rand)
    end
  end

  test "sha256 random" do
    for _ <- 1..100 do
      key = random()
      rand = random()
      assert HMAC.hash(:sha256, key, rand) == :crypto.hmac(:sha256, key, rand)
    end
  end

  test "sha384 random" do
    for _ <- 1..100 do
      key = random()
      rand = random()
      assert HMAC.hash(:sha384, key, rand) == :crypto.hmac(:sha384, key, rand)
    end
  end

  test "sha512 random" do
    for _ <- 1..100 do
      key = random()
      rand = random()
      assert HMAC.hash(:sha512, key, rand) == :crypto.hmac(:sha512, key, rand)
    end
  end

  defp random do
    for _ <- 1..:rand.uniform(0xfff), into: <<>>, do: <<:rand.uniform(0xff)>>
  end
end
