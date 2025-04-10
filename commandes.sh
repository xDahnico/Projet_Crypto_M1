gradle run --args="-format DER tbs/DER/www.tbs-certificats.der \"tbs/DER/Sectigo Qualified Website Authentication CA E35.der\" \"tbs/DER/USERTrust ECC Certification Authority.der\""

gradle run --args="-format PEM tbs/PEM/www.tbs-certificats.com 'tbs/PEM/Sectigo Qualified Website Authentication CA E35.crt' 'tbs/PEM/USERTrust ECC Certification Authority.crt'"

gradle run --args="-format PEM lemonde/PEM/_.lemonde.fr.crt 'lemonde/PEM/GlobalSign Atlas R3 DV TLS CA 2024 Q4.crt' 'lemonde/PEM/GlobalSign.crt'"

gradle run --args="-format DER lemonde/DER/_.lemonde.fr.crt 'lemonde/DER/GlobalSign Atlas R3 DV TLS CA 2024 Q4.crt' 'lemonde/DER/GlobalSign.crt'"