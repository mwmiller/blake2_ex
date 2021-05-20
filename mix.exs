defmodule Blake2.Mixfile do
  use Mix.Project

  def project do
    [
      app: :blake2,
      version: "1.0.4",
      elixir: "~> 1.7",
      name: "Blake2",
      source_url: "https://github.com/mwmiller/blake2_ex",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      deps: deps()
    ]
  end

  def application do
    []
  end

  defp deps do
    [
      {:ex_doc, "~> 0.23", only: :dev},
    ]
  end

  defp description do
    """
    BLAKE2 hash functions
    """
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README*", "LICENSE*"],
      maintainers: ["Matt Miller"],
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/mwmiller/blake2_ex",
        "RFC" => "https://tools.ietf.org/html/rfc7693"
      }
    ]
  end
end
