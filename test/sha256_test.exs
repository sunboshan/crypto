defmodule SHA256Test do
  use ExUnit.Case
  alias Crypto.Hash.SHA256
  doctest SHA256

  test "SHA256 empty" do
    assert SHA256.hash("") == <<227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85>>
  end

  test "SHA256 hello world" do
    assert SHA256.hash("Hello World!") == <<127, 131, 177, 101, 127, 241, 252, 83, 185, 45, 193, 129, 72, 161, 214, 93, 252, 45, 75, 31, 163, 214, 119, 40, 74, 221, 210, 0, 18, 109, 144, 105>>
  end

  test "SHA256 random" do
    for _ <- 1..100 do
      rand = random()
      assert SHA256.hash(rand) == :crypto.hash(:sha256, rand)
    end
  end

  test "SHA224 empty" do
    assert SHA256.hash224("") == <<209, 74, 2, 140, 42, 58, 43, 201, 71, 97, 2, 187, 40, 130, 52, 196, 21, 162, 176, 31, 130, 142, 166, 42, 197, 179, 228, 47>>
  end

  test "SHA224 hello world" do
    assert SHA256.hash224("Hello World!") == <<69, 117, 187, 78, 193, 41, 223, 99, 128, 206, 221, 230, 215, 18, 23, 254, 5, 54, 248, 255, 196, 225, 139, 202, 83, 10, 122, 27>>
  end

  test "SHA224 random" do
    for _ <- 1..100 do
      rand = random()
      assert SHA256.hash224(rand) == :crypto.hash(:sha224, rand)
    end
  end

  defp random do
    for _ <- 0..:rand.uniform(0xffff), into: <<>>, do: <<:rand.uniform(0xff)>>
  end
end
