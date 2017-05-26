defmodule MD5Test do
  use ExUnit.Case
  alias Crypto.Hash.MD5
  doctest MD5

  test "empty" do
    assert MD5.hash("") == <<212, 29, 140, 217, 143, 0, 178, 4, 233, 128, 9, 152, 236, 248, 66, 126>>
  end

  test "hello world" do
    assert MD5.hash("Hello World!") == <<237, 7, 98, 135, 83, 46, 134, 54, 94, 132, 30, 146, 191, 197, 13, 140>>
  end

  test "random" do
    for _ <- 1..100 do
      rand = random()
      assert MD5.hash(rand) == :crypto.hash(:md5, rand)
    end
  end

  defp random do
    for _ <- 0..:rand.uniform(0xffff), into: <<>>, do: <<:rand.uniform(0xff)>>
  end
end
