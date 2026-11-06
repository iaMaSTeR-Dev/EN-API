import { BankClientError, type BankReadOnlyClient } from '../client/bank-read-only-client.ts';
import type { BankCard, IbanInquiryResult, OwnerInquiryResult } from '../types.ts';
import { extractContentArray, getBankByPan } from './general-service.ts';

export class CardService {
  private client: BankReadOnlyClient;

  constructor(client: BankReadOnlyClient) {
    this.client = client;
  }

  /**
   * Retrieves all owned cards with masked PANs.
   */
  async getCards(): Promise<BankCard[]> {
    const raw = await this.client.getOwnedCards();
    const items = (raw.content as unknown[]) || [];

    return items.map((item: any) => ({
      cardUniqueId: String(item.cardUniqueId || item.id || item.uniqueId || ''),
      maskedPan: this.formatMaskedPan(item.pan || item.cardNumber || ''),
      title: String(item.title || item.cardTitle || 'کارت'),
      expDate: item.expDate ? String(item.expDate) : undefined,
      cardStatus: item.cardStatus ? String(item.cardStatus) : undefined,
      linkedIban: item.cardMainDepositIban ? String(item.cardMainDepositIban) : undefined,
      isDefault: item.defaultCard === true,
    }));
  }

  /**
   * Retrieves saved / favorite destination cards.
   */
  async getDestinationCards(): Promise<{ cardUniqueId?: string; pan: string; title: string; ownerName?: string }[]> {
    const raw = await this.client.getDestinationCards();
    const items = extractContentArray(raw?.content, 'destinationCards', 'cards');

    return items.map((item: any) => ({
      cardUniqueId: item.cardUniqueId || item.id ? String(item.cardUniqueId || item.id) : undefined,
      pan: this.formatMaskedPan(item.pan || item.cardNumber || ''),
      title: String(item.title || item.cardTitle || 'کارت مقصد'),
      ownerName: item.ownerName || item.destinationCardOwnerName ? String(item.ownerName || item.destinationCardOwnerName) : undefined,
    }));
  }

  /**
   * Inquires cardholder name for a destination PAN.
   * Leverages primary card inquiry (/en/api/card/inquiry?pan=) with automatic fallback
   * to PAN-to-IBAN inquiry (/en/api/iban/panToIban?pan=) and BIN-based issuing bank identification.
   */
  async inquireCardRecipient(pan: string): Promise<{ recipientName: string; bankName?: string; depositNumber?: string; linkedIban?: string }> {
    const cleanPan = pan.replace(/[\s-]/g, '').trim();
    const binBank = getBankByPan(cleanPan);

    // 1. Primary: Direct card inquiry endpoint (GET /en/api/card/inquiry?pan=)
    let primaryError: unknown;
    try {
      const raw = await this.client.inquireCard(cleanPan);
      const content = (raw?.content as any) || {};
      const recipientName = String(
        content.destinationCardOwnerName ||
        content.ownerName ||
        content.cardHolderName ||
        content.fullName ||
        content.name ||
        ''
      ).trim();

      if (recipientName) {
        return {
          recipientName,
          bankName: content.bankName ? String(content.bankName) : binBank.persianName,
        };
      }
    } catch (err) {
      primaryError = err;
    }

    // 2. Fallback: PAN-to-IBAN resolution (GET /en/api/iban/panToIban?pan=)
    // Bank Eghtesad Novin PWA uses this to resolve card owner and deposit/IBAN
    try {
      const ibanRaw = await this.client.convertPanToIban(cleanPan);
      const ibanContent = (ibanRaw?.content as any) || {};
      const pairs = Array.isArray(ibanContent.cardDepositAndIbans) ? ibanContent.cardDepositAndIbans : [];
      if (pairs.length > 0 && pairs[0]) {
        const first = pairs[0];
        const owner = String(first.depositOwnerName || first.ownerName || first.name || '').trim();
        if (owner) {
          return {
            recipientName: owner,
            bankName: binBank.persianName,
            depositNumber: first.depositNumber ? String(first.depositNumber) : undefined,
            linkedIban: first.iban ? String(first.iban) : undefined,
          };
        }
      }
    } catch {
      // Secondary fallback attempt failed; fall through to primary error evaluation
    }

    // 3. If primary threw an error, evaluate and rethrow with clear diagnostic details
    if (primaryError) {
      if (primaryError instanceof BankClientError) {
        const masked = cleanPan.length >= 16 ? `${cleanPan.slice(0, 6)}******${cleanPan.slice(12, 16)}` : cleanPan;
        const bankDesc = binBank.persianName ? ` [${binBank.persianName}]` : '';
        const msg = primaryError.statusCode && primaryError.statusCode >= 500
          ? `Bank card inquiry for ${masked}${bankDesc} returned HTTP ${primaryError.statusCode}. Shetab interbank card inquiry may be temporarily unavailable or restricted on this gateway.`
          : primaryError.message;

        throw new BankClientError(
          msg,
          primaryError.statusCode,
          primaryError.bankCode,
          primaryError.isAuthError,
          primaryError.isNetworkError,
          primaryError.isRateLimited
        );
      }
      throw primaryError;
    }

    // If neither returned an error nor recipientName
    return {
      recipientName: '',
      bankName: binBank.persianName,
    };
  }

  /**
   * Inquires IBAN owner information and associated deposit.
   */
  async inquireIban(iban: string): Promise<IbanInquiryResult> {
    const raw = await this.client.inquireIban(iban);
    const content = (raw.content as any) || {};

    return {
      iban,
      depositNumber: content.depositNumber ? String(content.depositNumber) : undefined,
      ownerName: String(content.ownerName || content.accountOwnerName || content.title || ''),
      bankName: content.bankName ? String(content.bankName) : undefined,
      status: content.status ? String(content.status) : undefined,
    };
  }

  /**
   * Converts card PAN to associated IBAN.
   */
  async convertPanToIban(pan: string): Promise<string> {
    const raw = await this.client.convertPanToIban(pan);
    const content = (raw.content as any) || {};
    return String(content.iban || content.sheba || content.value || '');
  }

  /**
   * Converts deposit number to IBAN.
   */
  async convertDepositToIban(depositNumber: string): Promise<string> {
    const raw = await this.client.convertDepositToIban(depositNumber);
    const content = (raw.content as any) || {};
    return String(content.iban || content.sheba || content.value || '');
  }

  /**
   * Converts IBAN to deposit number.
   */
  async convertIbanToDeposit(iban: string): Promise<string> {
    const raw = await this.client.convertIbanToDeposit(iban);
    const content = (raw.content as any) || {};
    return String(content.depositNumber || content.number || content.value || '');
  }

  /**
   * Unified owner inquiry for a Card PAN, IBAN, or Deposit Number.
   */
  async inquireOwner(identifier: string): Promise<OwnerInquiryResult> {
    const rawId = (identifier || '').trim();
    if (!rawId) {
      throw new Error('Identifier cannot be empty.');
    }
    const clean = rawId.replace(/[\s-]/g, '');

    // 1. If 16 digits, treat as Card PAN
    if (/^\d{16}$/.test(clean)) {
      const cardRes = await this.inquireCardRecipient(clean);
      return {
        identifierType: 'CARD',
        identifier: clean,
        ownerName: cardRes.recipientName,
        bankName: cardRes.bankName,
      };
    }

    // 2. If starts with IR (or 24 digits), treat as IBAN
    if (/^(IR)?\d{24}$/i.test(clean)) {
      const formattedIban = clean.toUpperCase().startsWith('IR') ? clean.toUpperCase() : `IR${clean}`;
      const ibanRes = await this.inquireIban(formattedIban);
      return {
        identifierType: 'IBAN',
        identifier: formattedIban,
        ownerName: ibanRes.ownerName,
        bankName: ibanRes.bankName,
        depositNumber: ibanRes.depositNumber,
      };
    }

    // 3. Deposit number: must be alphanumeric with optional hyphens/dots/slashes
    if (!/^[a-zA-Z0-9.\-_/]{5,64}$/.test(rawId)) {
      throw new Error(`Unrecognized identifier format: "${identifier}". Must be a 16-digit card PAN, 24/26-character IBAN, or valid deposit number.`);
    }

    // Convert deposit to IBAN first, then inquire owner
    try {
      const iban = await this.convertDepositToIban(rawId);
      if (iban && iban.toUpperCase().startsWith('IR')) {
        const ibanRes = await this.inquireIban(iban.toUpperCase());
        return {
          identifierType: 'DEPOSIT',
          identifier: rawId,
          ownerName: ibanRes.ownerName,
          bankName: ibanRes.bankName,
          depositNumber: rawId,
          iban: iban.toUpperCase(),
        };
      }
    } catch {
      // Fallback
    }

    // Check owned deposits if available
    try {
      const owned = await this.client.getOwnedDeposits();
      const list = Array.isArray(owned?.content) ? owned.content : [];
      const match = list.find((d: any) => d.depositNumber === rawId || d.depositNumber?.replace(/\D/g, '') === clean);
      if (match && match.iban) {
        const ibanRes = await this.inquireIban(match.iban);
        return {
          identifierType: 'DEPOSIT',
          identifier: rawId,
          ownerName: ibanRes.ownerName || match.title || '',
          bankName: ibanRes.bankName || 'بانک اقتصاد نوین',
          depositNumber: rawId,
          iban: match.iban,
        };
      }
    } catch {
      // Best-effort
    }

    throw new Error(`Owner inquiry failed for deposit "${rawId}": unable to resolve associated IBAN.`);
  }

  /**
   * Queries real-time balance for an owned card.
   */
  async getCardBalance(cardIdentifier: string): Promise<{
    cardUniqueId: string;
    balance: number;
    availableBalance: number;
    currency: string;
    balanceFormatted: string;
    availableBalanceFormatted: string;
  }> {
    const cleanId = (cardIdentifier || '').trim();
    if (!cleanId) {
      throw new Error('Card identifier cannot be empty.');
    }

    let targetUniqueId = cleanId;
    const cards = await this.getCards();
    const cleanDigits = cleanId.replace(/\D/g, '');
    const match = cards.find(
      (c) =>
        c.cardUniqueId === cleanId ||
        (cleanDigits.length >= 16 && c.maskedPan.replace(/\D/g, '') === cleanDigits)
    );
    if (match) {
      targetUniqueId = match.cardUniqueId;
    }

    const raw = await this.client.getCardBalance(targetUniqueId);
    const content = (raw?.content as any) || {};
    const bal = Number(content.balance ?? content.currentBalance ?? 0);
    const avail = Number(content.availableBalance ?? bal);
    const currency = String(content.currency || 'IRR');

    return {
      cardUniqueId: targetUniqueId,
      balance: !isNaN(bal) ? bal : 0,
      availableBalance: !isNaN(avail) ? avail : 0,
      currency,
      balanceFormatted: `${(!isNaN(bal) ? bal : 0).toLocaleString('en-US')} ${currency}`,
      availableBalanceFormatted: `${(!isNaN(avail) ? avail : 0).toLocaleString('en-US')} ${currency}`,
    };
  }

  /**
   * Queries transaction statement for an owned card.
   */
  async getCardStatement(
    cardIdentifier: string,
    options?: { page?: number; limit?: number; fromDate?: string; toDate?: string }
  ): Promise<{ transactions: any[]; totalCount?: number }> {
    const cleanId = (cardIdentifier || '').trim();
    if (!cleanId) {
      throw new Error('Card identifier cannot be empty.');
    }

    let targetUniqueId = cleanId;
    const cards = await this.getCards();
    const cleanDigits = cleanId.replace(/\D/g, '');
    const match = cards.find(
      (c) =>
        c.cardUniqueId === cleanId ||
        (cleanDigits.length >= 16 && c.maskedPan.replace(/\D/g, '') === cleanDigits)
    );
    if (match) {
      targetUniqueId = match.cardUniqueId;
    }

    const payload: Record<string, unknown> = {
      cardUniqueId: targetUniqueId,
      page: options?.page ?? 0,
      limit: options?.limit ?? 20,
    };
    if (options?.fromDate) payload.fromDate = options.fromDate;
    if (options?.toDate) payload.toDate = options.toDate;

    const raw = await this.client.getCardStatement(targetUniqueId, payload);
    const content = (raw?.content as any) || {};
    const transactions = Array.isArray(content.transactions)
      ? content.transactions
      : Array.isArray(content.statements)
      ? content.statements
      : Array.isArray(content)
      ? content
      : [];

    return {
      transactions,
      totalCount: typeof content.totalCount === 'number' ? content.totalCount : transactions.length,
    };
  }

  /**
   * Formats a 16-digit PAN into a masked string (e.g. 6274-12**-****-1234).
   */
  private formatMaskedPan(rawPan: string): string {
    const digits = rawPan.replace(/\D/g, '');
    if (digits.length >= 16) {
      return `${digits.slice(0, 6)}******${digits.slice(12, 16)}`;
    }
    return rawPan;
  }
}
