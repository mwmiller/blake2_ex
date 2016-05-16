defmodule Blake2.Mixfile do
  use Mix.Project

  def project do
    [app: :blake2,
     version: "0.1.0",
     elixir: "~> 1.2",
     name: "Blake2",
     source_url: "https://github.com/mwmiller/blake2_ex",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     description: description,
     package: package,
     deps: deps]
  end

  def application do
    []
  end

  defp deps do
    [
      {:earmark, "~> 0.2", only: :dev},
      {:ex_doc, "~> 0.11", only: :dev},
      {:power_assert, "~> 0.0.8", only: :test},
    ]
  end

  defp description do
    """
    BLAKE2 hash functions
    """
  end

  defp package do
    [
     files: ["lib", "mix.exs", "README*", "LICENSE*", ],
     maintainers: ["Matt Miller"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/mwmiller/blake2_ex",
              "RFC"    => "https://tools.ietf.org/html/rfc7693",
             }
    ]
  end

end
