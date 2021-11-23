#!/bin/sh

read val < test/fake_gpio/gpio27

val=$(( $val ^ 1 ))
echo $val > test/fake_gpio/gpio27
cat test/fake_gpio/gpio27
