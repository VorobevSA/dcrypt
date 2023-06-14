# [PBKDF2, AES256, SHA3] Encryption and decryption of texts on the command line, on golang 

## Build

Classic go build
```
go build
```
## Algorithm

1. Form a key based on a password using the - PBKDF2 algorithm, repeat this operation N times, where N is the checksum of the password modulo 64. Not a constant number of iterations helps protect against rainbow tables.
For PBKDF2, we use SHA 3-512 as a hash function.

2. Encrypt/We decrypt the information using the AES256 algorithm, the number of iterations is also determined dynamically by the password checksum modulo 8.


## Command list

* ```-s -secret``` - the message that needs to be encrypted 
* ```-m -message``` - the message that needs to be decrypted
* ```-p -passkey``` - password, required field
* ```-salt``` - change salt, preferably at least 8 characters
## Example

Encrypt
```
./dcrypt -p=testpass -s="poem mother laugh brush balcony eight endorse winter sense nasty shaft erosion tell debate caught balcony inflict cupboard jaguar route unlock fuel biology tobacco" 
AngAQp+qG4fX1IGLAUBMVzDOJEN/iYylCB3TwXTFBfIqaQ8RZnfbMMF23ym9XcD9oaWCfOCQiXsdJP+dHEyCAkhYXHCzGAUsLgNaZfKzT4CWcZNur+cWDXuSxsF8MR6MRc6FTct+OsEP+QAs3IgrnHUWSRpcuF7qla7yS8XAQk9rnA7hBHMJQs+QOT/qAp7/W46mr1OhHm2H+a15husW93SQWry8Jf4qpru3NeuQuhaXkYGEvrqWRgwmUKM/9Yc0QwTHw8R0XOXnejgS8/9pepYp4Z1hvIl4rB9q7MRt/4+x7vu/v8LeGPjc1I5W0gXgwiZQbQDMN6Sn1twx3BU7aLR9GecFQiQ3Trz+cDIcQBGU2y2nvKHo70Oi9P/5g6e3VlSrtNMaezj9lmjv5jomuQjo8NpKP3XpkPVZ8ET8a90W0wMMTA6FXtm2Id+6xtKtg0ybgwb8SYJasRpZyArADn9wd3qZPn6ityQcpe1lFdcgmsPbRHchXOfzhl0t7mHZxGtWnlIXvVjm23cUGPWkKkxUTWQ7EYNHEjDy7jhSpgK8/8GOmAMQFn51rmIdBc0B5qcdU/7H3dr9+aei4MCBInRpfQ9L6xjQU0oP9XBoYGUSVxju3vz4D8Sb3oX2YSTcFxE7xj47xat6mGp6vFn6FqE3UxvFBxV5uUg7i5brVM9yLkShDP5qYEuNiIlMI3gp0gKXAf/Uzr1uuYGzfo7i5POa0y8poppJbJ0EdHy60VXcLvDytYhNcFqruIysJUg18wm6fqc3S6EcetPK9ZaC9BFKWkvrl8OOPiYwBbipKQ+/Zwu/L3DbX8FQNy3Tc4RkF7CLnfA1MqNxiojwlsNc78S9asqGTnU9GXIRBx5jbv8ySqPJBSXTVVcDTukws0RjAvCle5T85HFIx4hFhLqvvxe+1PMS8kktKb7E4z9J5VHxhcIjpVMQZJPqu5KvHZZl692O8hFXK5ANuG43YBHLc62Iq2fcYfTUYPXkR9FSqde/3eh2yUEz1DA7Dm13+dVoR3yzSp/Rr69buSKDLQ1xYOYV0dpWG8XRo+korKTvhHnPBMVtJ8JDXFKbEN7PP815ijDa7AIXWV99Zv3cjzWht4+ne2l8JHvnLswMUvEtSUKt8h5hbN7grgDFmn4cfIEmpKCc6kKcShHvFwOvSbA3Gov4EAzTxXzccCrNVCg4RT/cGFoUWty7HBsANuAHr+XAsz0epEIVc7bxHKXszWLJru+piqkxazQv9KYkNy8AKYEDBlKqKEPJiIgEL8incrcYjfhrqNRX/WZGv+1LDQ30bA8/Vy/VRoFH4gBcjrcr7iO/OWXCkb1mVz7j7eMk3YFi7t5tn8FtmsLvTJZkVAwp9TAVNPCRDNZB67br0wSA1nEWIIFNdRXKJRi4t0Zs0X+CyRWiDvHV763+Hz8dk5ybmSXyXges4wWtWCuadIA/cBMJwPaJJ6hOs2AHssnI0d9GBxVYPred+pY+g/ZRqwzZyDIAZE33wxR8TAFIBzbNDrQxsaGroI43N2XbwCAEUTaw8z3j855SYe5Appdk+rq56RapVKQLJuAU0tNToeVZxL+3qK08/IL9SSgORWWhrgU1EcFKmT1q2gYZ7FCiMW69jP7ejwAMSA/ZkAMGOY4XKjhYuZKiTsROl4Fzb9x8et5Z
```
Decrypt
```
./dcrypt -p=testpass -m=AngAQp+qG4fX1IGLAUBMVzDOJEN/iYylCB3TwXTFBfIqaQ8RZnfbMMF23ym9XcD9oaWCfOCQiXsdJP+dHEyCAkhYXHCzGAUsLgNaZfKzT4CWcZNur+cWDXuSxsF8MR6MRc6FTct+OsEP+QAs3IgrnHUWSRpcuF7qla7yS8XAQk9rnA7hBHMJQs+QOT/qAp7/W46mr1OhHm2H+a15husW93SQWry8Jf4qpru3NeuQuhaXkYGEvrqWRgwmUKM/9Yc0QwTHw8R0XOXnejgS8/9pepYp4Z1hvIl4rB9q7MRt/4+x7vu/v8LeGPjc1I5W0gXgwiZQbQDMN6Sn1twx3BU7aLR9GecFQiQ3Trz+cDIcQBGU2y2nvKHo70Oi9P/5g6e3VlSrtNMaezj9lmjv5jomuQjo8NpKP3XpkPVZ8ET8a90W0wMMTA6FXtm2Id+6xtKtg0ybgwb8SYJasRpZyArADn9wd3qZPn6ityQcpe1lFdcgmsPbRHchXOfzhl0t7mHZxGtWnlIXvVjm23cUGPWkKkxUTWQ7EYNHEjDy7jhSpgK8/8GOmAMQFn51rmIdBc0B5qcdU/7H3dr9+aei4MCBInRpfQ9L6xjQU0oP9XBoYGUSVxju3vz4D8Sb3oX2YSTcFxE7xj47xat6mGp6vFn6FqE3UxvFBxV5uUg7i5brVM9yLkShDP5qYEuNiIlMI3gp0gKXAf/Uzr1uuYGzfo7i5POa0y8poppJbJ0EdHy60VXcLvDytYhNcFqruIysJUg18wm6fqc3S6EcetPK9ZaC9BFKWkvrl8OOPiYwBbipKQ+/Zwu/L3DbX8FQNy3Tc4RkF7CLnfA1MqNxiojwlsNc78S9asqGTnU9GXIRBx5jbv8ySqPJBSXTVVcDTukws0RjAvCle5T85HFIx4hFhLqvvxe+1PMS8kktKb7E4z9J5VHxhcIjpVMQZJPqu5KvHZZl692O8hFXK5ANuG43YBHLc62Iq2fcYfTUYPXkR9FSqde/3eh2yUEz1DA7Dm13+dVoR3yzSp/Rr69buSKDLQ1xYOYV0dpWG8XRo+korKTvhHnPBMVtJ8JDXFKbEN7PP815ijDa7AIXWV99Zv3cjzWht4+ne2l8JHvnLswMUvEtSUKt8h5hbN7grgDFmn4cfIEmpKCc6kKcShHvFwOvSbA3Gov4EAzTxXzccCrNVCg4RT/cGFoUWty7HBsANuAHr+XAsz0epEIVc7bxHKXszWLJru+piqkxazQv9KYkNy8AKYEDBlKqKEPJiIgEL8incrcYjfhrqNRX/WZGv+1LDQ30bA8/Vy/VRoFH4gBcjrcr7iO/OWXCkb1mVz7j7eMk3YFi7t5tn8FtmsLvTJZkVAwp9TAVNPCRDNZB67br0wSA1nEWIIFNdRXKJRi4t0Zs0X+CyRWiDvHV763+Hz8dk5ybmSXyXges4wWtWCuadIA/cBMJwPaJJ6hOs2AHssnI0d9GBxVYPred+pY+g/ZRqwzZyDIAZE33wxR8TAFIBzbNDrQxsaGroI43N2XbwCAEUTaw8z3j855SYe5Appdk+rq56RapVKQLJuAU0tNToeVZxL+3qK08/IL9SSgORWWhrgU1EcFKmT1q2gYZ7FCiMW69jP7ejwAMSA/ZkAMGOY4XKjhYuZKiTsROl4Fzb9x8et5Z
poem mother laugh brush balcony eight endorse winter sense nasty shaft erosion tell debate caught balcony inflict cupboard jaguar route unlock fuel biology tobacco
```
