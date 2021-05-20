defmodule Blake2 do
  import Bitwise

  @moduledoc """
  BLAKE2 hash functions

  Implementing "Blake2b" and "Blake2s" as described in [RFC7693](https://tools.ietf.org/html/rfc7693)

  Note that, at present, this only supports full message hashing and no OPTIONAL features
  of BLAKE2.
  """

  defp modulo(n, 64), do: n |> rem(18_446_744_073_709_551_616)
  defp modulo(n, 32), do: n |> rem(4_294_967_296)

  defp rotations(64), do: {32, 24, 16, 63}
  defp rotations(32), do: {16, 12, 8, 7}

  defp mix(v, i, [x, y], bc) do
    [a, b, c, d] = extract_elements(v, i, [])
    {r1, r2, r3, r4} = rotations(bc)

    a = modulo(a + b + x, bc)
    d = rotr(bxor(d, a), r1, bc)
    c = modulo(c + d, bc)
    b = rotr(bxor(b, c), r2, bc)
    a = modulo(a + b + y, bc)
    d = rotr(bxor(d, a), r3, bc)
    c = modulo(c + d, bc)
    b = rotr(bxor(b, c), r4, bc)

    update_elements(v, [a, b, c, d], i)
  end

  defp rotr(x, n, b), do: modulo(bxor(x >>> n, x <<< (b - n)), b)

  defp compress(h, m, t, f, b) do
    v = (h ++ iv(b)) |> List.to_tuple()

    rounds =
      case b do
        32 -> 10
        _ -> 12
      end

    v
    |> update_elements(
      [
        bxor(elem(v, 12), modulo(t, b)),
        bxor(elem(v, 13), t >>> b),
        if(f, do: bxor(elem(v, 14), mask(b)), else: elem(v, 14))
      ],
      [12, 13, 14]
    )
    |> mix_rounds(m, rounds, rounds, b)
    |> update_state(h)
  end

  defp mask(64), do: 0xFFFFFFFFFFFFFFFF
  defp mask(32), do: 0xFFFFFFFF

  defp update_state(v, h), do: update_state_list(v, h, 0, [])
  defp update_state_list(_v, [], _i, acc), do: acc |> Enum.reverse()

  defp update_state_list(v, [h | t], i, acc),
    do: update_state_list(v, t, i + 1, [h |> bxor(elem(v, i)) |> bxor(elem(v, i + 8)) | acc])

  defp mix_rounds(v, _m, 0, _c, _b), do: v

  defp mix_rounds(v, m, n, c, b) do
    s = sigma(c - n)
    msg_word_pair = fn x -> [elem(m, elem(s, 2 * x)), elem(m, elem(s, 2 * x + 1))] end

    v
    |> mix([0, 4, 8, 12], msg_word_pair.(0), b)
    |> mix([1, 5, 9, 13], msg_word_pair.(1), b)
    |> mix([2, 6, 10, 14], msg_word_pair.(2), b)
    |> mix([3, 7, 11, 15], msg_word_pair.(3), b)
    |> mix([0, 5, 10, 15], msg_word_pair.(4), b)
    |> mix([1, 6, 11, 12], msg_word_pair.(5), b)
    |> mix([2, 7, 8, 13], msg_word_pair.(6), b)
    |> mix([3, 4, 9, 14], msg_word_pair.(7), b)
    |> mix_rounds(m, n - 1, c, b)
  end

  @doc """
  Blake2b hashing

  Note that the `output_size` is in bytes, not bits

  - 64 => Blake2b-512 (default)
  - 48 => Blake2b-384
  - 32 => Blake2b-256

  Per the specification, any `output_size` between 1 and 64 bytes is supported.
  """
  @spec hash2b(binary, pos_integer, binary) :: binary | :error
  def hash2b(m, output_size \\ 64, secret_key \\ ""), do: hash(m, 64, output_size, secret_key)

  @doc """
  Blake2s hashing

  Note that the `output_size` is in bytes, not bits

  - 32 => Blake2s-256 (default)
  - 24 => Blake2b-192
  - 16 => Blake2b-128

  Per the specification, any `output_size` between 1 and 32 bytes is supported.
  """
  @spec hash2s(binary, pos_integer, binary) :: binary | :error
  def hash2s(m, output_size \\ 32, secret_key \\ ""), do: hash(m, 32, output_size, secret_key)

  defp hash(m, b, output_size, secret_key)
       when byte_size(secret_key) <= b and output_size <= b and output_size >= 1 do
    ll = byte_size(m)
    kk = byte_size(secret_key)

    key =
      case {ll, kk} do
        {0, 0} -> <<0>>
        _ -> secret_key
      end

    key
    |> pad(b * 2)
    |> (&(&1 <> m)).()
    |> pad(b * 2)
    |> block_msg(b)
    |> msg_hash(ll, kk, output_size, b)
  end

  # Wrong-sized stuff
  defp hash(_m, _secret_key, _b, _output_size), do: :error

  defp pad(b, n) when b |> byte_size |> rem(n) == 0, do: b
  defp pad(b, n), do: pad(b <> <<0>>, n)

  defp block_msg(m, bs), do: break_blocks(m, {}, [], bs)
  defp break_blocks(<<>>, {}, blocks, _bs), do: blocks |> Enum.reverse()

  defp break_blocks(to_break, block_tuple, blocks, bs) do
    <<i::unsigned-little-integer-size(bs), rest::binary>> = to_break

    {block_tuple, blocks} =
      case tuple_size(block_tuple) do
        15 -> {{}, [Tuple.insert_at(block_tuple, 15, i) | blocks]}
        n -> {Tuple.insert_at(block_tuple, n, i), blocks}
      end

    break_blocks(rest, block_tuple, blocks, bs)
  end

  defp msg_hash(blocks, ll, kk, nn, b) do
    [h0 | hrest] = iv(b)

    [h0 |> bxor(0x01010000) |> bxor(kk <<< 8) |> bxor(nn) | hrest]
    |> process_blocks(blocks, kk, ll, 1, b)
    |> list_to_binary(<<>>, b)
    |> binary_part(0, nn)
  end

  defp list_to_binary([], bin, _b), do: bin

  defp list_to_binary([h | t], bin, b),
    do: list_to_binary(t, bin <> (h |> :binary.encode_unsigned(:little) |> pad(div(b, 8))), b)

  defp process_blocks(h, [final_block], kk, ll, _n, b) when kk == 0,
    do: compress(h, final_block, ll, true, b)

  defp process_blocks(h, [final_block], kk, ll, _n, b) when kk != 0,
    do: compress(h, final_block, ll + b * 2, true, b)

  defp process_blocks(h, [d | rest], kk, ll, n, b),
    do: process_blocks(compress(h, d, n * b * 2, false, b), rest, kk, ll, n + 1, b)

  defp extract_elements(_v, [], a), do: a |> Enum.reverse()
  defp extract_elements(v, [this | rest], a), do: extract_elements(v, rest, [elem(v, this) | a])

  defp update_elements(v, [], []), do: v

  defp update_elements(v, [n | m], [i | j]),
    do: v |> Tuple.delete_at(i) |> Tuple.insert_at(i, n) |> update_elements(m, j)

  # Initialization vector
  defp iv(64),
    do: [
      0x6A09E667F3BCC908,
      0xBB67AE8584CAA73B,
      0x3C6EF372FE94F82B,
      0xA54FF53A5F1D36F1,
      0x510E527FADE682D1,
      0x9B05688C2B3E6C1F,
      0x1F83D9ABFB41BD6B,
      0x5BE0CD19137E2179
    ]

  defp iv(32),
    do: [
      0x6A09E667,
      0xBB67AE85,
      0x3C6EF372,
      0xA54FF53A,
      0x510E527F,
      0x9B05688C,
      0x1F83D9AB,
      0x5BE0CD19
    ]

  # Word schedule permutations
  defp sigma(0), do: {00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
  defp sigma(1), do: {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
  defp sigma(2), do: {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}
  defp sigma(3), do: {07, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8}
  defp sigma(4), do: {09, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}
  defp sigma(5), do: {02, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9}
  defp sigma(6), do: {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}
  defp sigma(7), do: {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10}
  defp sigma(8), do: {06, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}
  defp sigma(9), do: {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}
  defp sigma(10), do: {00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
  defp sigma(11), do: {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
end
