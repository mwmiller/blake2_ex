defmodule Blake2Test do
  use ExUnit.Case
  doctest Blake2
  import VectorHelper

  test "RFC 2b example" do
    m = "abc"

    h =
      from_hex("""
       BA 80 A5 3F 98 1C 4D 0D 6A 27 97 B6 9F 12 F6 E9
       4C 21 2F 14 68 5A C4 B7 4B 12 BB 6F DB FF A2 D1
       7D 87 C5 39 2A AB 79 2D C2 52 D5 DE 45 33 CC 95
       18 D3 8A A8 DB F1 92 5A B9 23 86 ED D4 00 99 23
      """)

    assert Blake2.hash2b(m) == h
  end

  test "RFC 2s example" do
    m = "abc"

    h =
      from_hex("""
       50 8C 5E 8C 32 7C 14 E2 E1 A7 2B A3 4E EB 45 2F
       37 45 8B 20 9E D6 3A 29 4D 99 9B 4C 86 67 59 82
      """)

    assert Blake2.hash2s(m) == h
  end

  test "repo 2b test vectors" do
    k = RepoVectors.key2b()

    test_2b = fn
      [], [], _fun ->
        :noop

      [m | ins], [h | hashes], fun ->
        assert m |> Blake2.hash2b(64, k) |> tag_from_bin == h
        fun.(ins, hashes, fun)
    end

    test_2b.(RepoVectors.ins(), RepoVectors.hashes2b(), test_2b)
  end

  test "repo 2s test vectors" do
    k = RepoVectors.key2s()

    test_2s = fn
      [], [], _fun ->
        :noop

      [m | ins], [h | hashes], fun ->
        assert m |> Blake2.hash2s(32, k) |> tag_from_bin == h
        fun.(ins, hashes, fun)
    end

    test_2s.(RepoVectors.ins(), RepoVectors.hashes2s(), test_2s)
  end
end
