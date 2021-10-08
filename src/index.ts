import * as crypto from "crypto";

/**
 * Implements Shamir Secret Sharing (8 bit support max shares 255(+1))
 * Originating From : https://github.com/grempe/secrets.js
 *
 * @class Nitr0genSecrets
 */
export class Nitr0genSecrets {
  /**
   * Exponenets
   *
   * @private
   * @type {{[index: string]: number}}
   * @memberof Nitr0genSecrets
   */
  private exps: { [index: string]: number } = {};

  /**
   * Logarithm
   *
   * @private
   * @type {{[index: string]: number}}
   * @memberof Nitr0genSecrets
   */
  private logs: { [index: string]: number } = {};

  constructor() {
    let x = 1;

    // Generate Expos & Logs, Currently 8 byte support only.
    for (let i = 0; i < 256; i++) {
      this.exps[i] = x;
      this.logs[x] = i;
      x = x << 1; // Left shift assignment
      if (x >= 256) {
        x = x ^ 29; // Bitwise XOR assignment
        x = x & 255; // Bitwise AND assignment
      }
    }
  }

  /**
   * Generate shares from the data that needs to be secret
   *
   * @param {string} secret
   * @param {number} shares
   * @param {number} threshold
   * @returns
   * @memberof kbxShamirSecrets
   */
  public generate(secret: string, shares: number, threshold: number) {
    // Convert Data for processing
    const stringIntArray = this.convertNumStringToIntArray(secret);

    // Setup Points
    const x: string[] = new Array(shares);

    // Convert Data into Points (why map that isn't used!)
    for (let i = stringIntArray.length; i--; ) {
      let subs = this.extractShares(
        stringIntArray.splice(i)[0],
        shares,
        threshold
      );
      for (let i = shares; i--; ) {
        if (!x[i]) {
          x[i] = subs[i].x.toString(16).padStart(2, "0");
        }
        x[i] += subs[i].y.toString(16).padStart(2, "0");
      }
    }
    return x;
  }

  /**
   * Combine shares back into some kind of data
   * Cannot use events because they all get called at the end
   *
   * @param {string[]} shares
   * @returns
   * @memberof Nitr0genSecrets
   */
  public async combine(shares: string[]) {
    // Ready Points
    const x: number[] = [];
    const y: number[][] = [];

    // Returned data string (hex)
    let result: string = "";

    // Loop the shares
    //shares.forEach((share, i) => {
    for (let i = 0; i < shares.length; i++) {
      const share = shares[i];

      const id = parseInt(shares[i].slice(0, 2), 16);      
      const data = share.slice(2);

      // Make sure share id doesn't exist in array already
      if (x.indexOf(id) === -1) {
        // Add Share to X and get position
        let idPos = x.push(id) - 1;

        // Convert into int array
        let splitShare = this.convertNumStringToIntArray(data);

        // Loop integers to assign points
        //splitShare.forEach((splShare, i) => {
        for (let i = 0; i < splitShare.length; i++) {
          // Make sure y points array exists
          //if (!y[i]) y[i] = [];
          y[i] = y[i] || [];
          y[i][idPos] = splitShare[i];
        }
      }
    }
    // Loop y Points
    for (let i = 0; i < y.length; i++) {
      //y.forEach((e, i) => {
      result = this.lagrange(x, y[i]).toString(2).padStart(8, "0") + result;
    } //);

    // Return results as hex
    return this.bin2hex(result);
  }

  /**
   * Calculate the Lagrange of a polynomial
   *
   * @private
   * @param {number[]} x
   * @param {number[]} y
   * @returns
   * @memberof Nitr0genSecrets
   */
  private lagrange(x: number[], y: number[]) {
    let sum: number = 0;
    let product: number;

    // Loop Each x point across y
    x.forEach((e, i) => {
      if (y[i]) {
        product = this.logs[y[i]];

        for (let j = 0; j < x.length; j++) {
          if (i !== j) {
            if (0 === x[j]) {
              // happens when computing a share that is in the list of shares used to compute it
              product = -1; // fix for a zero product term, after which the sum should be sum^0 = sum, not sum^1
              break;
            }
            product =
              (product + this.logs[0 ^ x[j]] - this.logs[e ^ x[j]] + 255) % 255; // to make sure it's not negative
          }
        }

        // though exps[-1]= undefined and undefined ^ anything = anything in
        // chrome, this behavior may not hold everywhere, so do the check
        sum = product === -1 ? sum : sum ^ this.exps[product];
      }
    });
    return sum;
  }

  /**
   * Hex to Binary String
   *
   * @private
   * @param {string} hex
   * @returns {string}
   * @memberof Nitr0genSecrets
   */
  private hex2bin(hex: string): string {
    return parseInt(hex, 16).toString(2).padStart(4, "0");
  }

  /**
   * Binary String to Hex
   *
   * @private
   * @param {string} bin
   * @returns {string}
   * @memberof Nitr0genSecrets
   */
  private bin2hex(bin: string): string {
    let hex = "";
    for (let i = bin.length; i >= 4; i -= 4) {
      const num = parseInt(bin.slice(i - 4, i), 2);
      if (isNaN(num)) {
        throw new Error("Invalid binary character.");
      }
      hex = num.toString(16) + hex;
    }
    return hex;
  }

  /**
   * Extract shares points on polynomial with finite coefficient.
   *
   * @private
   * @param {number} s
   * @param {number} numSecrets
   * @param {number} threshold
   * @returns {{x: number; y: number}[]}
   * @memberof kbxShamirSecrets
   */
  private extractShares(
    s: number,
    numSecrets: number,
    threshold: number
  ): { x: number; y: number }[] {
    const shares = [];
    //const coeffs: number[] = [s, ...this.seeded];
    const coeffs: number[] = [s];

    if (coeffs.length === 1) {
      // Build Coeefs for the requested threshold
      for (let i = 1; i < threshold; i++) {
        coeffs[i] = parseInt(this.rngBinary(), 2);
      }
    }

    // Loop shares to create x y points
    for (let i = 1, len = numSecrets + 1; i < len; i++) {
      shares[i - 1] = {
        x: i,
        y: this.horner(i, coeffs),
      };
    }
    return shares;
  }

  /**
   * Horner's Method (Polynomials evaluating)
   *
   * @private
   * @param {number} x
   * @param {number[]} coeffs
   * @returns {number}
   * @memberof kbxShamirSecrets
   */
  private horner(x: number, coeffs: number[]): number {
    const logx = this.logs[x];
    let fx = coeffs.length - 1;
    for (let i = coeffs.length - 1; i--; ) {
      fx = this.exps[(logx + this.logs[fx]) % 255] ^ coeffs[i];
    }
    return fx;
  }

  /**
   * Generate Random Hex Value
   *
   * @private
   * @returns {string}
   * @memberof kbxShamirSecrets
   */
  private rngBinary(): string {
    return this.construct(crypto.randomBytes(1).toString("hex"));
  }

  /**
   * Construct Valid Random Value
   *
   * @private
   * @param {string} rHex
   * @returns {(string | null)}
   * @memberof kbxShamirSecrets
   */
  private construct(rHex: string): string {
    let str = "";

    // Convert hex byte to binary representation
    [...rHex].forEach((e) => {
      const parsedInt = Math.abs(parseInt(e, 16));      
      str += parsedInt.toString(2).padStart(4, "0");
    });

    // Make sure not all 0's
    if (/^0*$/.test(str)) {
      // Call "self" again to get better value
      return this.rngBinary();
    }
    return str;
  }

  /**
   * Convert number string into a integer array
   *
   * @private
   * @param {string} str
   * @returns {number[]}
   * @memberof Nitr0genSecrets
   */
  private convertNumStringToIntArray(str: string): number[] {
    const strArray = [...str];
    const parts: number[] = [];
    let tmp: string | null = null;
    for (let i = 0, len = strArray.length; i < len; i++) {
      if (tmp) {
        parts.push(parseInt(tmp + this.hex2bin(strArray[i]), 2));
        tmp = null;
      } else {
        tmp = this.hex2bin(strArray[i]);
      }
    }
    return parts;
  }
}
