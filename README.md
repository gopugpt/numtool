# numtool

Phone number OSINT CLI for Termux. Number validate, carrier/region lookup aur multiple API scanners.

## Install
    pkg install python git
    pip install -r requirements.txt
    mkdir -p ~/.config/numtool
    cp keys.env.example ~/.config/numtool/keys.env
    # phir keys.env me apni keys bharo

## Usage
Numbers E164 format me do (country code ke saath).

    python numtool.py "+919981307896"
    python numtool.py "+919981307896" --local-only
    python numtool.py -i nums.txt --local-only --csv out.csv
    python numtool.py "+919981307896" -a

## Flags
    -i FILE        ek line par ek number
    -s SCANNER     specific scanner
    -a             jitni keys set hain, sab chalao
    --local-only   sirf offline lookup
    -o FILE        JSON output
    --csv FILE     CSV summary
    --json         JSON stdout
    --rate N       rate limit
    --no-cache     cache ignore karo

## Keys
Numverify, Veriphone, AbstractAPI, IPQS, Google CSE — sabka free tier hai.
Bina key ke scanners skip ho jate hain.

## License
MIT
