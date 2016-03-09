defmodule Blake2 do
  import Bitwise

  @moduledoc """
  BLAKE2 hash function

  Implementing "Blake2b" as described in [RFC7693](https://tools.ietf.org/html/rfc7693)

  Note that, at present, this only supports full message hashing and no OPTIONAL features
  of BLAKE2.
  """

  defp mix(v,i,[x,y]) do
    [a,b,c,d] = extract_elements(v,i,[])

    a = (a + b + x) |> rem(18446744073709551616) # mod 2^64
    d = (d ^^^ a)   |> rotr(32)
    c = (c + d)     |> rem(18446744073709551616)
    b = (b ^^^ c)   |> rotr(24)
    a = (a + b + y) |> rem(18446744073709551616)
    d = (d ^^^ a)   |> rotr(16)
    c = (c + d)     |> rem(18446744073709551616)
    b = (b ^^^ c)   |> rotr(63)

    update_elements(v, [a,b,c,d], i)
  end

  defp rotr(x,n), do: ((x >>> n) ^^^ (x <<< (64 - n))) |> rem(18446744073709551616)

  defp compress(h,m,t,f) do
    v = h++iv |> List.to_tuple
    update_elements(v,[elem(v,12) ^^^ (rem(t,18446744073709551616)),
                           elem(v,13) ^^^ (t >>> 64),
                           (if f, do: elem(v,14) ^^^ 0xFFFFFFFFFFFFFFFF, else: elem(v,14))
                          ], [12,13,14])
      |> mix_rounds(m,12)
      |> update_state(h)
  end

  defp update_state(v,h), do: update_state_list(v,h,0,[])
  defp update_state_list(_v,[],_i,acc), do: acc |> Enum.reverse
  defp update_state_list(v,[h|t],i,acc), do: update_state_list(v,t,i+1,[h ^^^ elem(v,i) ^^^ elem(v,i+8)|acc])

  defp mix_rounds(v,_m, 0), do: v
  defp mix_rounds(v,m,n) do
    s = sigma(12 - n)
    msg_word_pair = fn(x) -> [elem(m,elem(s,2*x)), elem(m,elem(s,2*x+1))] end
    v |> mix([0, 4,  8, 12], msg_word_pair.(0))
      |> mix([1, 5,  9, 13], msg_word_pair.(1))
      |> mix([2, 6, 10, 14], msg_word_pair.(2))
      |> mix([3, 7, 11, 15], msg_word_pair.(3))
      |> mix([0, 5, 10, 15], msg_word_pair.(4))
      |> mix([1, 6, 11, 12], msg_word_pair.(5))
      |> mix([2, 7,  8, 13], msg_word_pair.(6))
      |> mix([3, 4,  9, 14], msg_word_pair.(7))
      |> mix_rounds(m,n-1)
  end
  @doc """
  Blake2b hashing

  Note that the `output_size` is in bytes, not bits

  - 64 => Blake2b-512 (default)
  - 48 => Blake2b-384
  - 32 => Blake2b-256

  Per the specification, any `output_size` between 1 and 64 bytes is supported.
  """
  @spec hash(binary,binary,pos_integer) :: binary | :error
  def hash(m,secret_key \\ "", output_size \\ 64)
  def hash(m,secret_key, output_size) when byte_size(secret_key) <= 64 and output_size <= 64 and output_size >= 1 do
     ll = byte_size(m)
     kk = byte_size(secret_key)
     if ll == 0 and kk == 0, do: secret_key = <<0>> # Silly special case, will be padded out
     secret_key |> pad(128)
                |> (&(&1<>m)).()
                |> pad(128)
                |> block_msg
                |> msg_hash(ll,kk,output_size)
  end
  def hash(_m,_secret_key,_output_size), do: :error # Wrong-sized stuff

  defp pad(b,n) when (byte_size(b) |> rem(n)) == 0, do: b
  defp pad(b,n), do: pad(b<><<0>>, n)

  defp block_msg(m), do: break_blocks(m, {}, [])
  defp break_blocks(<<>>, {}, blocks), do: blocks |> Enum.reverse
  defp break_blocks(<<i::unsigned-little-integer-size(64), rest::binary>>, block_tuple, blocks) do
      {block_tuple, blocks} = case tuple_size(block_tuple) do
                                15 -> { {}, [Tuple.insert_at(block_tuple,15,i)|blocks]}
                                n  -> { Tuple.insert_at(block_tuple,n,i) , blocks }
                              end
      break_blocks(rest, block_tuple, blocks)
  end

  defp msg_hash(blocks, ll, kk, nn) do
    [h0|hrest] = iv
    [h0 ^^^ 0x01010000 ^^^ (kk <<< 8) ^^^ nn|hrest]
      |> process_blocks(blocks,kk,ll,1)
      |> list_to_binary(<<>>)
      |> binary_part(0,nn)
  end

  defp list_to_binary([], bin), do: bin
  defp list_to_binary([h|t], bin), do: list_to_binary(t, bin<>(h |> :binary.encode_unsigned(:little) |> pad(8)))

  defp process_blocks(h,[final_block], kk, ll, _n)  when kk == 0,  do: compress(h, final_block, ll, true)
  defp process_blocks(h,[final_block], kk, ll, _n)  when kk != 0,  do: compress(h, final_block, ll+128, true)
  defp process_blocks(h,[d|rest],kk,ll,n), do: process_blocks(compress(h, d, n * 128, false), rest, kk,ll,n+1)


  defp extract_elements(_v,[], a), do:  a |> Enum.reverse
  defp extract_elements(v,[this|rest], a), do: extract_elements(v,rest,[elem(v,this)|a])

  defp update_elements(v,[],[]), do: v
  defp update_elements(v,[n|m],[i|j]), do: v |> Tuple.delete_at(i) |> Tuple.insert_at(i,n) |> update_elements(m,j)

  # Initialization vector
  defp iv, do: [ 0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1, 0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179 ]

  # Word schedule permutations
  defp sigma(0),  do: {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 }
  defp sigma(1),  do: { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
  defp sigma(2),  do: { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 }
  defp sigma(3),  do: {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 }
  defp sigma(4),  do: {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 }
  defp sigma(5),  do: {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 }
  defp sigma(6),  do: { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 }
  defp sigma(7),  do: { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 }
  defp sigma(8),  do: {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 }
  defp sigma(9),  do: { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
  defp sigma(10), do: {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 }
  defp sigma(11), do: { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }

end
