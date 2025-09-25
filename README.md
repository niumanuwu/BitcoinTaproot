# Bitcoin Taproot Implementation with Merkle Tree and Witness Path Spend

A basic implementation for two leaves in a merkle tree on Bitcoin. Witness path spend is also included for each leaf. 

# Leaf One
The first leaf is governed by a timelock and public key match. Once the timelock has expired, the assigned public key can withdraw the UTXO.

# Leaf Two
The second leaf is structured with opcodes allowing a 2/3 signatures before accessing UTXO.


