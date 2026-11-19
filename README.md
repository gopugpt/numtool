# numtool

Phone number OSINT CLI for Termux. Validate numbers and look up carrier/region information, with optional third-party API scanners.

## Install

```sh
pkg install python git
pip install -r requirements.txt
mkdir -p ~/.config/numtool
cp keys.env.example ~/.config/numtool/keys.env
# Add your API keys to ~/.config/numtool/keys.env as needed.
```

## Usage

Use E.164 format with the country calling code.

```sh
python numtool.py "+12025550123" --local-only
python numtool.py "+12025550123" -a
python numtool.py -i my-numbers.txt --local-only --csv out.csv
```

`my-numbers.txt` should contain one number per line. Keep personal number lists local; `nums.txt` is ignored by Git.

## Options

- `-i FILE`: read one number per line
- `-s SCANNER`: select scanners
- `-a`: run scanners with configured keys
- `--local-only`: perform offline lookup only
- `-o FILE`: write JSON to a file
- `--csv FILE`: write a CSV summary
- `--json`: print JSON to stdout
- `--rate N`: delay in seconds between requests
- `--no-cache`: bypass the local cache

## API keys and privacy

Numverify, Veriphone, AbstractAPI, IPQS, and Google Custom Search require API keys. Scanners without configured keys are skipped. Online scanners send the queried phone number to the selected third-party service. Use this tool only with numbers you are authorized to look up, and review each provider's terms and privacy policy.

## License

MIT
