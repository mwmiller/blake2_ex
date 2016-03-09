defmodule Blake2Test do
  use PowerAssert
  doctest Blake2
  import VectorHelper

  test "RFC example" do
    m = "abc"
    h = from_hex """
                  BA 80 A5 3F 98 1C 4D 0D 6A 27 97 B6 9F 12 F6 E9
                  4C 21 2F 14 68 5A C4 B7 4B 12 BB 6F DB FF A2 D1
                  7D 87 C5 39 2A AB 79 2D C2 52 D5 DE 45 33 CC 95
                  18 D3 8A A8 DB F1 92 5A B9 23 86 ED D4 00 99 23
                 """

    assert Blake2.hash(m) == h

  end

  test "repo test vectors" do
    k = RepoVectors.key

    test_em = fn
              ([],[], _fun)              -> :noop
              ([m|ins], [h|hashes], fun) ->
                assert (Blake2.hash(m,k) |> tag_from_bin) == h
                fun.(ins, hashes, fun)
              end

    test_em.(RepoVectors.ins, RepoVectors.hashes, test_em)

  end

end
