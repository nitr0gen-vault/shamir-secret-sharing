import { randomBytes } from "crypto";
import { Nitr0genSecrets } from "../src/index";

(async () => {
  
  for (let i = 0; i < 10; i++) {
    console.log(`Running Test #${i+1}`);

    // New Object
    const nitr0genSecret = new Nitr0genSecrets();

    // Run Vars
    const dataLength = randomInteger(200, 500);
    const totalParts = randomInteger(4, 100);
    const totalRequired = randomInteger(2, totalParts);
    console.log(
      `Data length ${dataLength}, Parts ${totalParts}, Required ${totalRequired}`
    );

    const data = randomBytes(dataLength).toString("hex");

    // Create the secrets
    const secrets = await nitr0genSecret.generate(
      data,
      totalParts,
      totalRequired
    );

    // Combine random sample of secrets
    const results = await nitr0genSecret.combine(
      secrets.sort(() => 0.5 - Math.random()).slice(0, totalRequired)
    );

    // Validate
    if (data === results) {
      console.log("✔️", "\x1b[92m", "Test Past", "\x1b[0m");
    } else {
      console.log("❌", "\x1b[91m", "Test Failed", "\x1b[0m");
    }
  }
})();


/**
 * Helper function to select a number at psuedo random
 *
 * @param {number} min
 * @param {number} max
 * @returns
 */
function randomInteger(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
