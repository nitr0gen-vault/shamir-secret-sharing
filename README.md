# Nitr0gen Shamir Secret Sharing

This is Nitr0gen's implementation of Shamir's secret sharing algorithm. Nitr0gen uses this as part of its key storage vault solution.

Original Paper : [How to share a secret](http://web.mit.edu/6.857/OldStuff/Fall03/ref/Shamir-HowToShareASecret.pdf) - By Adi Shamir


## How to split a secret

```typescript
// Init
const nitr0genSecret = new Nitr0genSecrets();

// String or hex can be passed
const splitMe = Buffer.from("Hello World").toString("hex");
const totalParts = 10;
const totalRequired = 5;

// Returns an array of strings
const secrets = await nitr0genSecret.generate(
  splitMe,
  totalParts,
  totalRequired
);
```

## How to combine a secret

```typescript
// Init
const nitr0genSecret = new Nitr0genSecrets();

// Array from the split above
const secrets = []

// As long as the array has meets required length
// the result will contain the hex version of "Hello World"
const result = await notabox.combine(secrets);
```
