### Security
- **A cloud assistant model never keeps an address.** Choosing the Anthropic
  provider now clears any `base_url` kept from an earlier choice. The client
  already ignored it (the key only ever went to Anthropic's own address); this
  makes the stored setting say the same, so it can never become the place a key
  is sent.
