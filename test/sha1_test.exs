defmodule SHA1Test do
  use ExUnit.Case
  alias Crypto.Hash.SHA1
  doctest SHA1

  test "empty" do
    assert SHA1.hash("") == <<218, 57, 163, 238, 94, 107, 75, 13, 50, 85, 191, 239, 149, 96, 24, 144, 175, 216, 7, 9>>
  end

  test "hello world" do
    assert SHA1.hash("Hello World!") == <<46, 247, 189, 230, 8, 206, 84, 4, 233, 125, 95, 4, 47, 149, 248, 159, 28, 35, 40, 113>>
  end

  test "random" do
    for _ <- 1..100 do
      rand = random()
      assert SHA1.hash(rand) == :crypto.hash(:sha, rand)
    end
  end

  defp random do
    for _ <- 0..:rand.uniform(0xffff), into: <<>>, do: <<:rand.uniform(0xff)>>
  end
end
