// Elk JavaScript example: blink GPIO 2 ten times.
// Use let; statements end with semicolons.
gpio_mode(2, "output");
for (let i = 0; i < 10; i = i + 1) {
  gpio_write(2, true);
  if (!delay_ms(250)) break;
  gpio_write(2, false);
  if (!delay_ms(250)) break;
}
print("blink finished");
