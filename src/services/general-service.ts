import { BankClientError, type BankReadOnlyClient } from '../client/bank-read-only-client.ts';
import type {
  UserProfile,
  BankInfo,
  DestinationContact,
  ScheduledTransfer,
  ChequeItem,
  LoanFacility,
  LoanInstallment,
  AdvertisementBanner,
  UtilityBill,
  TopupItem,
  PackageItem,
} from '../types.ts';
import { parseTransactionTimestamp } from './account-service.ts';

export const BANK_EN_NAMES: Record<string, string> = {
  EN: 'Bank Eghtesad Novin',
  BMI: 'Bank Melli Iran',
  BML: 'Bank Mellat',
  BPI: 'Bank Pasargad',
  BSM: 'Bank Saman',
  BPR: 'Bank Parsian',
  BTE: 'Bank Tejarat',
  BRE: 'Bank Refah Kargaran',
  BSP: 'Bank Sepah',
  BSD: 'Bank Saderat Iran',
  BMS: 'Bank Maskan',
  PB: 'Post Bank Iran',
  BSN: 'Bank Sina',
  BAY: 'Bank Ayandeh',
  BKA: 'Bank Karafarin',
  BSR: 'Bank Sarmayeh',
  BSH: 'Bank Shahr',
  BIZ: 'Bank Iran Zamin',
  BDY: 'Bank Dey',
  QMB: 'Gharzolhasaneh Mehr Iran',
  QMR: 'Gharzolhasaneh Resalat',
  BME: 'Middle East Bank',
  BGR: 'Gardeshgari Bank',
  BLU: 'Blu Bank (Saman)',
};

export const BANK_BIN_MAP: Record<string, { code: string; nameFa: string; nameEn: string }> = {
  '627412': { code: 'EN', nameFa: 'بانک اقتصاد نوین', nameEn: 'Bank Eghtesad Novin' },
  '603799': { code: 'BMI', nameFa: 'بانک ملی ایران', nameEn: 'Bank Melli Iran' },
  '610433': { code: 'BML', nameFa: 'بانک ملت', nameEn: 'Bank Mellat' },
  '502229': { code: 'BPI', nameFa: 'بانک پاسارگاد', nameEn: 'Bank Pasargad' },
  '639347': { code: 'BPI', nameFa: 'بانک پاسارگاد', nameEn: 'Bank Pasargad' },
  '621986': { code: 'BSM', nameFa: 'بانک سامان', nameEn: 'Bank Saman' },
  '622106': { code: 'BPR', nameFa: 'بانک پارسیان', nameEn: 'Bank Parsian' },
  '639194': { code: 'BPR', nameFa: 'بانک پارسیان', nameEn: 'Bank Parsian' },
  '585983': { code: 'BTE', nameFa: 'بانک تجارت', nameEn: 'Bank Tejarat' },
  '589463': { code: 'BRE', nameFa: 'بانک رفاه کارگران', nameEn: 'Bank Refah Kargaran' },
  '589210': { code: 'BSP', nameFa: 'بانک سپه', nameEn: 'Bank Sepah' },
  '603769': { code: 'BSD', nameFa: 'بانک صادرات ایران', nameEn: 'Bank Saderat Iran' },
  '628023': { code: 'BMS', nameFa: 'بانک مسکن', nameEn: 'Bank Maskan' },
  '627760': { code: 'PB', nameFa: 'پست بانک ایران', nameEn: 'Post Bank Iran' },
  '639346': { code: 'BSN', nameFa: 'بانک سینا', nameEn: 'Bank Sina' },
  '636214': { code: 'BAY', nameFa: 'بانک آینده', nameEn: 'Bank Ayandeh' },
  '627488': { code: 'BKA', nameFa: 'بانک کارآفرین', nameEn: 'Bank Karafarin' },
  '639607': { code: 'BSR', nameFa: 'بانک سرمایه', nameEn: 'Bank Sarmayeh' },
  '504706': { code: 'BSH', nameFa: 'بانک شهر', nameEn: 'Bank Shahr' },
  '505785': { code: 'BIZ', nameFa: 'بانک ایران زمین', nameEn: 'Bank Iran Zamin' },
  '502938': { code: 'BDY', nameFa: 'بانک دی', nameEn: 'Bank Dey' },
  '606373': { code: 'QMB', nameFa: 'بانک قرض‌الحسنه مهر ایران', nameEn: 'Gharzolhasaneh Mehr Iran' },
  '504172': { code: 'QMR', nameFa: 'بانک قرض‌الحسنه رسالت', nameEn: 'Gharzolhasaneh Resalat' },
  '585947': { code: 'BME', nameFa: 'بانک خاورمیانه', nameEn: 'Middle East Bank' },
  '505416': { code: 'BGR', nameFa: 'بانک گردشگری', nameEn: 'Gardeshgari Bank' },
};

export const IBAN_CODE_MAP: Record<string, { code: string; nameFa: string; nameEn: string }> = {
  '055': { code: 'EN', nameFa: 'بانک اقتصاد نوین', nameEn: 'Bank Eghtesad Novin' },
  '017': { code: 'BMI', nameFa: 'بانک ملی ایران', nameEn: 'Bank Melli Iran' },
  '012': { code: 'BML', nameFa: 'بانک ملت', nameEn: 'Bank Mellat' },
  '057': { code: 'BPI', nameFa: 'بانک پاسارگاد', nameEn: 'Bank Pasargad' },
  '056': { code: 'BSM', nameFa: 'بانک سامان', nameEn: 'Bank Saman' },
  '054': { code: 'BPR', nameFa: 'بانک پارسیان', nameEn: 'Bank Parsian' },
  '018': { code: 'BTE', nameFa: 'بانک تجارت', nameEn: 'Bank Tejarat' },
  '013': { code: 'BRE', nameFa: 'بانک رفاه کارگران', nameEn: 'Bank Refah Kargaran' },
  '015': { code: 'BSP', nameFa: 'بانک سپه', nameEn: 'Bank Sepah' },
  '019': { code: 'BSD', nameFa: 'بانک صادرات ایران', nameEn: 'Bank Saderat Iran' },
  '014': { code: 'BMS', nameFa: 'بانک مسکن', nameEn: 'Bank Maskan' },
  '021': { code: 'PB', nameFa: 'پست بانک ایران', nameEn: 'Post Bank Iran' },
  '059': { code: 'BSN', nameFa: 'بانک سینا', nameEn: 'Bank Sina' },
  '062': { code: 'BAY', nameFa: 'بانک آینده', nameEn: 'Bank Ayandeh' },
  '053': { code: 'BKA', nameFa: 'بانک کارآفرین', nameEn: 'Bank Karafarin' },
  '058': { code: 'BSR', nameFa: 'بانک سرمایه', nameEn: 'Bank Sarmayeh' },
  '061': { code: 'BSH', nameFa: 'بانک شهر', nameEn: 'Bank Shahr' },
  '069': { code: 'BIZ', nameFa: 'بانک ایران زمین', nameEn: 'Bank Iran Zamin' },
  '066': { code: 'BDY', nameFa: 'بانک دی', nameEn: 'Bank Dey' },
  '060': { code: 'QMB', nameFa: 'بانک قرض‌الحسنه مهر ایران', nameEn: 'Gharzolhasaneh Mehr Iran' },
  '070': { code: 'QMR', nameFa: 'بانک قرض‌الحسنه رسالت', nameEn: 'Gharzolhasaneh Resalat' },
  '078': { code: 'BME', nameFa: 'بانک خاورمیانه', nameEn: 'Middle East Bank' },
  '064': { code: 'BGR', nameFa: 'بانک گردشگری', nameEn: 'Gardeshgari Bank' },
};

export function getBankByPan(pan: string): { bankCode: string; persianName: string; bankName: string } {
  const clean = pan.replace(/[\s-]/g, '');
  const bin = clean.slice(0, 6);
  const found = BANK_BIN_MAP[bin];
  if (found) {
    return { bankCode: found.code, persianName: found.nameFa, bankName: found.nameEn };
  }
  return { bankCode: '', persianName: 'بانک عضو شتاب', bankName: 'Shetab Member Bank' };
}

export function getBankByIban(iban: string): string | undefined {
  const clean = iban.replace(/[\s-]/g, '').toUpperCase();
  if (clean.startsWith('IR') && clean.length >= 7) {
    const code = clean.slice(4, 7);
    return IBAN_CODE_MAP[code]?.nameFa;
  }
  return undefined;
}

export function mapBankIdentifier(id: string): string {
  const norm = id.toLowerCase().replace(/[\s-_]/g, '');
  if (norm.includes('novin') || norm.includes('eghtesad')) return 'بانک اقتصاد نوین';
  if (norm.includes('melli')) return 'بانک ملی ایران';
  if (norm.includes('mellat')) return 'بانک ملت';
  if (norm.includes('pasargad')) return 'بانک پاسارگاد';
  if (norm.includes('saman')) return 'بانک سامان';
  if (norm.includes('parsian')) return 'بانک پارسیان';
  if (norm.includes('tejarat')) return 'بانک تجارت';
  if (norm.includes('sepah')) return 'بانک سپه';
  if (norm.includes('refah')) return 'بانک رفاه کارگران';
  if (norm.includes('saderat')) return 'بانک صادرات ایران';
  if (norm.includes('maskan')) return 'بانک مسکن';
  if (norm.includes('post')) return 'پست بانک ایران';
  if (norm.includes('sina')) return 'بانک سینا';
  if (norm.includes('ayandeh')) return 'بانک آینده';
  if (norm.includes('karafarin')) return 'بانک کارآفرین';
  if (norm.includes('sarmayeh')) return 'بانک سرمایه';
  if (norm.includes('shahr')) return 'بانک شهر';
  if (norm.includes('iranzamin')) return 'بانک ایران زمین';
  if (norm.includes('dey')) return 'بانک دی';
  if (norm.includes('resalat')) return 'بانک قرض‌الحسنه رسالت';
  if (norm.includes('mehr')) return 'بانک قرض‌الحسنه مهر ایران';
  if (norm.includes('gardeshgari')) return 'بانک گردشگری';
  if (norm.includes('khavarmianeh') || norm.includes('middleeast')) return 'بانک خاورمیانه';
  return id;
}

/**
 * Safely extracts an array from explicitly supported bank response structures.
 *
 * Supported structures:
 * 1. Direct array: Array.isArray(content) -> returns content
 * 2. Envelope object: { [candidateKey]: array } -> returns that array
 * 3. Legitimate empty cases:
 *    - content is null or undefined -> returns []
 *    - candidateKey is present on content but its value is null or undefined -> returns []
 *    - content is an empty object {} -> returns []
 *
 * Any other structure (primitive values, wrong property types, or unrecognized object envelopes)
 * is rejected with BankClientError so malformed responses are never masked as successful empty results.
 */
export function extractContentArray(content: unknown, ...candidateKeys: string[]): unknown[] {
  // 1. Legitimate null or undefined content (e.g. empty bank result set)
  if (content === null || content === undefined) {
    return [];
  }

  // 2. Direct array
  if (Array.isArray(content)) {
    return content;
  }

  // 3. Primitive wrong types are invalid structures
  if (typeof content !== 'object') {
    throw new BankClientError(
      `Malformed bank response: expected array or object payload, received ${typeof content}.`,
      200
    );
  }

  const obj = content as Record<string, unknown>;

  // 4. Empty envelope object {} is a legitimate empty container
  if (Object.keys(obj).length === 0) {
    return [];
  }

  // 5. Look strictly for candidate keys passed by the caller
  if (candidateKeys.length > 0) {
    for (const key of candidateKeys) {
      if (key in obj) {
        const val = obj[key];
        if (Array.isArray(val)) {
          return val;
        }
        if (val === null || val === undefined) {
          return [];
        }
        throw new BankClientError(
          `Malformed bank response: property '${key}' is of type ${typeof val}, expected an array.`,
          200
        );
      }
    }

    // Object has keys, but none match the explicitly supported candidate keys
    const availableKeys = Object.keys(obj).slice(0, 5).join(', ');
    throw new BankClientError(
      `Malformed bank response envelope: expected one of [${candidateKeys.join(', ')}], found [${availableKeys}].`,
      200
    );
  }

  throw new BankClientError(
    'Malformed bank response: payload object does not contain a supported list structure.',
    200
  );
}

/**
 * Normalizes operator names from bank codes or Persian/English descriptions.
 */
export function normalizeOperatorName(rawOp?: unknown): string | undefined {
  if (typeof rawOp !== 'string' || !rawOp.trim()) return undefined;
  const trimmed = rawOp.trim();
  const lower = trimmed.toLowerCase();
  if (lower === 'hamrahaval' || lower === 'hamrah_aval' || trimmed === 'همراه اول') return 'همراه اول';
  if (lower === 'irancell' || trimmed === 'ایرانسل') return 'ایرانسل';
  if (lower === 'rightel' || trimmed === 'رایتل') return 'رایتل';
  if (lower === 'shatel' || lower === 'shatelmobile' || trimmed === 'شاتل موبایل') return 'شاتل موبایل';
  return trimmed;
}

export class GeneralService {
  private client: BankReadOnlyClient;

  constructor(client: BankReadOnlyClient) {
    this.client = client;
  }

  /**
   * Retrieves and normalizes customer profile summary.
   */
  async getProfile(): Promise<UserProfile> {
    const raw = await this.client.getProfileSummary();
    const content = (raw.content as any) || {};

    const firstName = String(content.firstName || content.name || '').trim();
    const lastName = String(content.lastName || content.family || '').trim();
    const fullName = String(
      content.fullName ||
      (firstName && lastName ? `${firstName} ${lastName}` : '') ||
      content.title ||
      'مشتری بانک اقتصاد نوین'
    ).trim();

    const rawLastLogin = content.lastLoginDate || content.lastLoginTime;
    const lastLoginParsed = rawLastLogin ? parseTransactionTimestamp(rawLastLogin) : undefined;

    return {
      cif: content.cif ? String(content.cif).trim() : undefined,
      username: content.username ? String(content.username).trim() : undefined,
      fullName,
      firstName: firstName || undefined,
      lastName: lastName || undefined,
      nationalCode: content.nationalCode ? String(content.nationalCode).trim() : undefined,
      mobileNumber: content.mobileNumber || content.phoneNumber ? String(content.mobileNumber || content.phoneNumber).trim() : undefined,
      lastLoginDate: lastLoginParsed?.jalaliDate
        ? `${lastLoginParsed.jalaliDate} ${lastLoginParsed.jalaliTime || ''}`.trim()
        : (rawLastLogin ? String(rawLastLogin) : undefined),
      userType: content.userType ? String(content.userType).trim() : undefined,
    };
  }

  /**
   * Retrieves and normalizes Iranian bank directory.
   */
  async getBanks(search?: string): Promise<BankInfo[]> {
    const raw = await this.client.getBankList();
    const items = extractContentArray(raw.content, 'banksBaseInfo');

    const banks: BankInfo[] = items
      .filter((item: any) => item && typeof item === 'object')
      .map((item: any) => {
        const key = String(item.key || item.bankCode || item.code || item.id || '').trim();
        const persianName = String(
          item.nameFa || item.persianName || item.faName || item.title || item.name || ''
        ).trim();
        const enName = String(
          item.bankName || item.nameEn || item.enName || (key ? BANK_EN_NAMES[key.toUpperCase()] : '') || key || ''
        ).trim();
        const bins = Array.isArray(item.bins) ? item.bins.map(String) : [];

        return {
          bankCode: key,
          bankName: enName,
          persianName: persianName || enName || key,
          bins,
          logoUrl: item.logo || item.logoUrl
            ? String(item.logo || item.logoUrl)
            : undefined,
        };
      });

    if (search && search.trim().length > 0) {
      const q = search.trim().toLowerCase();

      return banks.filter(
        (b) =>
          b.bankName.toLowerCase().includes(q) ||
          b.persianName.includes(q) ||
          b.bankCode.includes(q) ||
          b.bins.some((bin) => bin.includes(q))
      );
    }

    return banks;
  }

  /**
   * Retrieves active dashboard banners and announcements.
   */
  async getBanners(type: string = 'PopUp'): Promise<AdvertisementBanner[]> {
    const raw = await this.client.getAdvertisements(type);
    const content = (raw.content as any) || {};
    const items = Array.isArray(content.advertisements)
      ? content.advertisements
      : Array.isArray(content)
        ? content
        : [];

    return items.map((item: any) => ({
      id: String(item.id || item.advertisementId || ''),
      title: String(item.title || item.name || 'پیام سیستم'),
      body: item.body ? String(item.body).replace(/<[^>]*>?/gm, '').trim() : undefined,
      type: item.type ? String(item.type) : type,
      imageUrl: item.image || item.imageUrl ? String(item.image || item.imageUrl) : undefined,
      linkUrl: item.link || item.url ? String(item.link || item.url) : undefined,
    }));
  }

  /**
   * Retrieves scheduled / recurring auto-transfers.
   */
  async getScheduledTransfers(type: 'NORMAL' | 'ACH' = 'NORMAL'): Promise<ScheduledTransfer[]> {
    const raw = await this.client.getAutoTransfers({ type, length: 50 });
    const content = (raw.content as any) || {};
    const items = Array.isArray(content.autoTransferModels)
      ? content.autoTransferModels
      : Array.isArray(content.autoTransferAchModels)
        ? content.autoTransferAchModels
        : Array.isArray(content)
          ? content
          : [];

    return items.map((item: any) => {
      const amount = Math.abs(Number(item.amount ?? item.transferAmount ?? 0));
      const term = item.autoTransferTerm || {};
      return {
        transferId: String(item.id || item.transferId || item.autoTransferId || ''),
        autoTransferType: type,
        sourceDepositNumber: String(item.sourceDepositNumber || item.depositNumber || ''),
        destinationNumber: String(item.destinationNumber || item.destinationIban || item.destNumber || ''),
        destinationOwnerName: item.destinationOwnerName ? String(item.destinationOwnerName) : undefined,
        amount,
        amountFormatted: `${amount.toLocaleString('en-US')} IRR`,
        reasonTitle: item.reasonTitle ? String(item.reasonTitle) : undefined,
        status: item.status ? String(item.status) : undefined,
        termType: term.termType ? String(term.termType) : undefined,
        termLength: typeof term.termLength === 'number' ? term.termLength : undefined,
        transactionCount: typeof term.transactionCount === 'number' ? term.transactionCount : undefined,
        startDate: term.startDate ? String(term.startDate) : undefined,
        nextDate: item.nextExecutionDate ? String(item.nextExecutionDate) : undefined,
      };
    });
  }

  /**
   * Retrieves Sayad national cheque cartable.
   */
  async getCheques(options?: { page?: number; limit?: number; status?: string }): Promise<ChequeItem[]> {
    const raw = await this.client.getSayadCheques(options);
    const content = (raw.content as any) || {};
    const items = Array.isArray(content.cheques)
      ? content.cheques
      : Array.isArray(content.cartableItems)
        ? content.cartableItems
        : Array.isArray(content.data)
          ? content.data
          : Array.isArray(content)
            ? content
            : [];

    return items.map((item: any) => {
      const amount = typeof item.amount === 'number' ? item.amount : Number(item.amount || 0);
      const absAmount = Math.abs(isNaN(amount) ? 0 : amount);
      const parsedDue = item.dueDate ? parseTransactionTimestamp(item.dueDate) : undefined;

      return {
        sayadId: item.sayadId || item.sayadNumber ? String(item.sayadId || item.sayadNumber) : undefined,
        chequeBookNumber: item.chequeBookNumber ? String(item.chequeBookNumber) : undefined,
        serialNumber: item.serialNumber || item.serial ? String(item.serialNumber || item.serial) : undefined,
        amount: absAmount > 0 ? absAmount : undefined,
        amountFormatted: absAmount > 0 ? `${absAmount.toLocaleString('en-US')} IRR` : undefined,
        dueDate: parsedDue?.gregorianDate || (item.dueDate ? String(item.dueDate) : undefined),
        jalaliDueDate: parsedDue?.jalaliDate,
        status: item.status ? String(item.status) : undefined,
        statusTitle: item.statusTitle || item.statusDesc ? String(item.statusTitle || item.statusDesc) : undefined,
        bankName: item.bankName ? String(item.bankName) : undefined,
        issuerName: item.issuerName || item.senderName ? String(item.issuerName || item.senderName) : undefined,
        receiverName: item.receiverName ? String(item.receiverName) : undefined,
        isDigital: item.isDigital === true,
      };
    });
  }

  /**
   * Retrieves single Sayad cheque detail.
   */
  async getChequeDetail(itemUniqueId: string): Promise<ChequeItem | null> {
    const cleanId = (itemUniqueId || '').trim();
    if (!cleanId) return null;

    const raw = await this.client.getSayadChequeDetail(cleanId);
    const item = (raw.content as any) || {};
    if (!item || typeof item !== 'object') return null;

    const amount = typeof item.amount === 'number' ? item.amount : Number(item.amount || 0);
    const absAmount = Math.abs(isNaN(amount) ? 0 : amount);
    const parsedDue = item.dueDate ? parseTransactionTimestamp(item.dueDate) : undefined;

    return {
      sayadId: item.sayadId || item.sayadNumber ? String(item.sayadId || item.sayadNumber) : undefined,
      chequeBookNumber: item.chequeBookNumber ? String(item.chequeBookNumber) : undefined,
      serialNumber: item.serialNumber || item.serial ? String(item.serialNumber || item.serial) : undefined,
      amount: absAmount > 0 ? absAmount : undefined,
      amountFormatted: absAmount > 0 ? `${absAmount.toLocaleString('en-US')} IRR` : undefined,
      dueDate: parsedDue?.gregorianDate || (item.dueDate ? String(item.dueDate) : undefined),
      jalaliDueDate: parsedDue?.jalaliDate,
      status: item.status ? String(item.status) : undefined,
      statusTitle: item.statusTitle || item.statusDesc ? String(item.statusTitle || item.statusDesc) : undefined,
      bankName: item.bankName ? String(item.bankName) : undefined,
      issuerName: item.issuerName || item.senderName ? String(item.issuerName || item.senderName) : undefined,
      receiverName: item.receiverName ? String(item.receiverName) : undefined,
      isDigital: item.isDigital === true,
    };
  }

  /**
   * Retrieves customer loans facilities.
   */
  async getLoans(): Promise<LoanFacility[]> {
    const raw = await this.client.getLoans();
    const items = (raw.content as unknown[]) || [];

    return items.filter((item: any) => item && typeof item === 'object').map((item: any) => {
      const totalAmount = Math.abs(Number(item.totalAmount ?? item.amount ?? 0));
      const remainAmount = Math.abs(Number(item.remainAmount ?? item.remainingAmount ?? 0));
      const installmentAmount = Math.abs(Number(item.installmentAmount ?? 0));

      return {
        loanNumber: String(item.loanNumber || item.loanId || item.id || ''),
        loanTitle: item.title || item.loanTitle ? String(item.title || item.loanTitle) : 'تسهیلات بانکی',
        totalAmount,
        totalAmountFormatted: `${totalAmount.toLocaleString('en-US')} IRR`,
        remainAmount,
        remainAmountFormatted: `${remainAmount.toLocaleString('en-US')} IRR`,
        installmentAmount: installmentAmount > 0 ? installmentAmount : undefined,
        installmentAmountFormatted: installmentAmount > 0 ? `${installmentAmount.toLocaleString('en-US')} IRR` : undefined,
        paidCount: typeof item.paidInstallmentsCount === 'number' ? item.paidInstallmentsCount : undefined,
        unpaidCount: typeof item.unpaidInstallmentsCount === 'number' ? item.unpaidInstallmentsCount : undefined,
        totalCount: typeof item.totalInstallmentsCount === 'number' ? item.totalInstallmentsCount : undefined,
      };
    });
  }

  /**
   * Retrieves installments schedule for a specific customer loan.
   */
  async getLoanInstallments(loanId: string): Promise<LoanInstallment[]> {
    const cleanId = (loanId || '').trim();
    if (!cleanId) return [];

    const raw = await this.client.getLoanInstallments(cleanId);
    const content = (raw.content as any) || {};
    const items = Array.isArray(content.installments)
      ? content.installments
      : Array.isArray(content)
        ? content
        : [];

    return items.map((item: any, idx: number) => {
      const amount = Math.abs(Number(item.amount ?? item.installmentAmount ?? 0));
      const parsedDue = item.dueDate ? parseTransactionTimestamp(item.dueDate) : undefined;
      const penalty = Number(item.penaltyAmount ?? 0);

      return {
        installmentNumber: typeof item.installmentNumber === 'number' ? item.installmentNumber : idx + 1,
        dueDate: parsedDue?.gregorianDate || (item.dueDate ? String(item.dueDate) : undefined),
        jalaliDueDate: parsedDue?.jalaliDate,
        amount,
        amountFormatted: `${amount.toLocaleString('en-US')} IRR`,
        isPaid: item.isPaid === true || item.paid === true || item.status === 'PAID',
        penaltyAmount: !isNaN(penalty) && penalty > 0 ? penalty : undefined,
        paymentDate: item.paymentDate ? String(item.paymentDate) : undefined,
      };
    });
  }

  /**
   * Aggregates saved destination accounts, cards, IBANs, and topups into a unified contact directory.
   */
  async getContacts(): Promise<DestinationContact[]> {
    const [depositsRes, ibansRes, cardsRes] = await Promise.allSettled([
      this.client.getDestinationDeposits(),
      this.client.getDestinationIbans(),
      this.client.getDestinationCards(),
    ]);

    const contacts: DestinationContact[] = [];

    // 1. Destination Deposits
    if (depositsRes.status === 'fulfilled') {
      const items = extractContentArray(depositsRes.value.content, 'destinationDeposits', 'deposits');
      for (const item of items) {
        if (!item || typeof item !== 'object') continue;
        const raw = item as Record<string, unknown>;
        const rawOwner = raw.ownerName || raw.depositOwnerName || raw.name || raw.title;
        contacts.push({
          type: 'deposit',
          title: String(raw.title || raw.depositTitle || 'سپرده مقصد'),
          value: String(raw.depositNumber || raw.number || ''),
          ownerName: rawOwner ? String(rawOwner) : undefined,
          bankName: raw.bankName ? String(raw.bankName) : 'بانک اقتصاد نوین',
          id: raw.id ? String(raw.id) : undefined,
        });
      }
    }

    // 2. Destination IBANs
    if (ibansRes.status === 'fulfilled') {
      const items = extractContentArray(ibansRes.value.content, 'destinationIbans', 'ibans');
      for (const item of items) {
        if (!item || typeof item !== 'object') continue;
        const raw = item as Record<string, unknown>;
        const ibanVal = String(raw.iban || raw.sheba || '');
        const rawBank = raw.bank ? String(raw.bank) : undefined;
        const derivedBank = rawBank ? mapBankIdentifier(rawBank) : (ibanVal ? getBankByIban(ibanVal) : undefined);
        const rawOwner = raw.ownerName || raw.depositOwnerName || raw.name || raw.title;
        contacts.push({
          type: 'iban',
          title: String(raw.title || raw.ibanTitle || 'شماره شبا مقصد'),
          value: ibanVal,
          ownerName: rawOwner ? String(rawOwner) : undefined,
          bankName: raw.bankName ? String(raw.bankName) : (derivedBank || 'بانک عضو شتاب'),
          id: raw.id ? String(raw.id) : undefined,
        });
      }
    }

    // 3. Destination Cards
    if (cardsRes.status === 'fulfilled') {
      const items = extractContentArray(cardsRes.value.content, 'destinationCards', 'cards');
      for (const item of items) {
        if (!item || typeof item !== 'object') continue;
        const raw = item as Record<string, unknown>;
        const rawPan = String(raw.pan || raw.cardNumber || '');
        const masked = rawPan.length >= 16 ? `${rawPan.slice(0, 6)}******${rawPan.slice(12, 16)}` : rawPan;
        const rawBank = raw.bank ? String(raw.bank) : undefined;
        const derivedBank = rawBank ? mapBankIdentifier(rawBank) : (rawPan ? getBankByPan(rawPan).persianName : undefined);
        const rawOwner = raw.ownerName || raw.destinationCardOwnerName || raw.cardHolderName || raw.name || raw.title;
        contacts.push({
          type: 'card',
          title: String(raw.title || raw.cardTitle || 'کارت مقصد'),
          value: masked,
          ownerName: rawOwner ? String(rawOwner) : undefined,
          bankName: raw.bankName ? String(raw.bankName) : (derivedBank || 'بانک عضو شتاب'),
          id: raw.id ? String(raw.id) : undefined,
        });
      }
    }

    return contacts;
  }

  /**
   * Retrieves saved utility bills.
   */
  async getBills(): Promise<UtilityBill[]> {
    const raw = await this.client.getSavedBills();
    const items = extractContentArray(raw?.content, 'userBills', 'billList', 'bills');

    return items
      .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
      .map((item) => ({
        id: String(item.id || item.billUniqueId || ''),
        billId: String(item.billId || item.billNumber || ''),
        payId: item.payId || item.paymentId ? String(item.payId || item.paymentId) : undefined,
        billType: item.billType ? String(item.billType) : undefined,
        title: item.title || item.name ? String(item.title || item.name) : 'قبض',
        amount: typeof item.amount === 'number' ? item.amount : undefined,
      }));
  }

  /**
   * Retrieves ACH (Paya/Satna) transfer reports.
   * Extracts transactions array from bank envelope and maps domain models.
   */
  async getAchReports(params?: { page?: number; limit?: number }): Promise<any[]> {
    const raw = await this.client.getAchTransferReport(params);
    const content = (raw?.content as any) || {};
    const rawList = Array.isArray(content.transactions)
      ? content.transactions
      : Array.isArray(content.achReports)
      ? content.achReports
      : Array.isArray(content)
      ? content
      : [];

    return rawList
      .filter((item: any): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
      .map((item: any) => {
        const rawDate = item.registerDate ?? item.date ?? item.transactionDate ?? item.timestamp;
        const timeInfo = rawDate ? parseTransactionTimestamp(rawDate) : undefined;

        return {
          reportId: item.referenceId ? String(item.referenceId) : item.id ? String(item.id) : undefined,
          referenceId: item.referenceId ? String(item.referenceId) : undefined,
          trackingNumber: item.trackingNumber ? String(item.trackingNumber) : (item.referenceId ? String(item.referenceId) : undefined),
          amount: typeof item.amount === 'number' ? item.amount : Number(item.amount || 0),
          status: String(item.status || item.transactionStatus || 'UNKNOWN'),
          sourceIban: item.sourceIbanNumber || item.sourceIban ? String(item.sourceIbanNumber || item.sourceIban) : undefined,
          destinationIban: item.destinationIbanNumber || item.destinationIban ? String(item.destinationIbanNumber || item.destinationIban) : undefined,
          destinationOwnerName: item.destinationOwnerName || item.ownerName ? String(item.destinationOwnerName || item.ownerName) : undefined,
          description: item.description || item.reasonTitle ? String(item.description || item.reasonTitle) : undefined,
          cancelable: Boolean(item.cancelable),
          jalaliDate: timeInfo?.jalaliDate,
          jalaliTime: timeInfo?.jalaliTime,
          gregorianDate: timeInfo?.gregorianDate,
          rawTimestamp: timeInfo?.rawTimestamp,
        };
      });
  }

  /**
   * Retrieves ACH transfer reasons.
   */
  async getAchReasons(): Promise<{ reasonCode: string; reasonTitle: string }[]> {
    const raw = await this.client.getAchReasons();
    const items = extractContentArray(raw?.content, 'reasons', 'items');
    return items
      .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
      .map((item) => ({
        reasonCode: String(item.reasonCode || item.code || ''),
        reasonTitle: String(item.reasonTitle || item.title || ''),
      }));
  }

  /**
   * Retrieves saved mobile top-up phone numbers.
   */
  async getTopups(): Promise<TopupItem[]> {
    const raw = await this.client.getSavedTopups();
    const items = extractContentArray(raw?.content, 'userTopups', 'topups', 'charges');
    return items
      .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
      .map((item) => {
        const phone = String(
          item.phoneNumber || item.mobileNumber || item.mobileNo || item.phone || ''
        ).trim();
        const operator = normalizeOperatorName(
          item.operator || item.operatorName || item.mobileOperatorType || item.operatorType
        );
        const title = item.title ? String(item.title).trim() : undefined;
        const date = item.date || item.creationDate || item.insertDate ? String(item.date || item.creationDate || item.insertDate).trim() : undefined;

        return {
          id: item.id ? String(item.id) : undefined,
          phoneNumber: phone,
          operator,
          title,
          date,
        };
      })
      .filter((topup) => topup.phoneNumber.length > 0);
  }

  /**
   * Retrieves saved mobile internet package numbers.
   */
  async getPackages(): Promise<PackageItem[]> {
    const raw = await this.client.getSavedPackages();
    const items = extractContentArray(raw?.content, 'userPackages', 'packages', 'internetPackages');
    return items
      .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
      .map((item) => {
        const phone = String(
          item.phoneNumber || item.mobileNumber || item.mobileNo || item.phone || ''
        ).trim();
        const operator = normalizeOperatorName(
          item.operator || item.operatorName || item.mobileOperatorType || item.operatorType
        );
        const packageTitle = item.packageTitle || item.title || item.description || item.packageName
          ? String(item.packageTitle || item.title || item.description || item.packageName).trim()
          : undefined;
        const title = item.title ? String(item.title).trim() : undefined;
        const date = item.date || item.creationDate || item.insertDate ? String(item.date || item.creationDate || item.insertDate).trim() : undefined;

        return {
          id: item.id ? String(item.id) : undefined,
          phoneNumber: phone,
          operator,
          packageTitle: packageTitle || title,
          title,
          date,
        };
      })
      .filter((pkg) => pkg.phoneNumber.length > 0);
  }

  /**
   * Retrieves active client sessions and connected devices.
   */
  async getActiveSessions(): Promise<any[]> {
    const raw = await this.client.retrieveActiveSessions();
    const items = extractContentArray(raw?.content, 'activeSessions', 'sessions', 'devices');
    return items
      .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
      .map((item) => {
        const rawLast = item.lastActivity || item.lastLoginTime || item.lastActivityTime;
        const parsed = rawLast ? parseTransactionTimestamp(rawLast) : undefined;
        return {
          id: item.id ? String(item.id) : undefined,
          sessionUid: item.sessionUid ? String(item.sessionUid) : undefined,
          deviceName: item.deviceName ? String(item.deviceName) : (item.deviceTitle ? String(item.deviceTitle) : 'دستگاه کاربر'),
          os: item.os ? String(item.os) : (item.platform ? String(item.platform) : undefined),
          browser: item.browser ? String(item.browser) : undefined,
          ip: item.ip ? String(item.ip) : undefined,
          lastActivity: parsed?.jalaliDate ? `${parsed.jalaliDate} ${parsed.jalaliTime || ''}`.trim() : (rawLast ? String(rawLast) : undefined),
          isCurrent: item.current === true || item.isCurrent === true,
        };
      });
  }

  /**
   * Retrieves user notification settings (email, SMS).
   */
  async getEmailSettings(): Promise<{
    useEmailForTransfer: boolean;
    useSmsForTransfer: boolean;
    maskedEmail?: string;
    maskedMobile?: string;
  }> {
    const raw = await this.client.getEmailSettings();
    const content = (raw?.content as any) || {};
    return {
      useEmailForTransfer: content.emailSetting === true || content.useEmailForTransfer === true,
      useSmsForTransfer: content.smsSetting === true || content.useSmsForTransfer === true,
      maskedEmail: content.maskedEmail ? String(content.maskedEmail) : undefined,
      maskedMobile: content.maskedMobile ? String(content.maskedMobile) : undefined,
    };
  }

  /**
   * Retrieves base utility bill types.
   */
  async getBillTypes(): Promise<any[]> {
    const raw = await this.client.getBillTypes();
    const items = extractContentArray(raw?.content, 'billTypes', 'types');
    return items
      .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
      .map((item) => ({
        typeKey: String(item.typeKey || item.key || item.id || ''),
        typeName: String(item.typeName || item.name || item.title || ''),
        code: item.code ? String(item.code) : undefined,
      }));
  }

  /**
   * Retrieves utility bill companies directory.
   */
  async getBillCompanies(): Promise<any[]> {
    const raw = await this.client.getBillCompanies();
    const items = extractContentArray(raw?.content, 'billCompanies', 'companies');
    return items
      .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
      .map((item) => ({
        companyId: String(item.companyId || item.id || item.code || ''),
        companyName: String(item.companyName || item.name || item.title || ''),
        billType: item.billType ? String(item.billType) : undefined,
      }));
  }

  /**
   * Inquires a specific utility bill by type and identifier.
   */
  async inquireBill(billType: string, billId: string): Promise<any> {
    const raw = await this.client.inquireBill(billType, billId);
    const content = (raw?.content as any) || {};
    const amount = Number(content.amount ?? content.billAmount ?? 0);
    return {
      billId: String(content.billId || content.id || billId),
      payId: String(content.payId || content.paymentId || ''),
      amount: !isNaN(amount) ? amount : 0,
      amountFormatted: `${(!isNaN(amount) ? amount : 0).toLocaleString('en-US')} IRR`,
      billType: content.billType ? String(content.billType) : billType,
      title: content.title || content.name ? String(content.title || content.name) : undefined,
      isPaid: content.isPaid === true || content.paid === true,
      paymentDate: content.paymentDate ? String(content.paymentDate) : undefined,
    };
  }

  /**
   * Retrieves system messages and user notifications.
   */
  async getMessages(pageSize: number = 500): Promise<any[]> {
    const raw = await this.client.getMessages(pageSize);
    const content = (raw?.content as any) || {};
    const rawList = Array.isArray(content.data)
      ? content.data
      : Array.isArray(content.messages)
      ? content.messages
      : Array.isArray(content)
      ? content
      : [];
    return rawList
      .filter((item: any) => item && typeof item === 'object')
      .map((item: any) => {
        const rawDate = item.date || item.sentDate || item.creationDate;
        const parsed = rawDate ? parseTransactionTimestamp(rawDate) : undefined;
        return {
          id: String(item.id || item.messageId || ''),
          title: String(item.title || item.subject || 'پیام سیستم'),
          body: item.body || item.text ? String(item.body || item.text).replace(/<[^>]*>?/gm, '').trim() : undefined,
          date: parsed?.jalaliDate ? `${parsed.jalaliDate} ${parsed.jalaliTime || ''}`.trim() : (rawDate ? String(rawDate) : undefined),
          isUnread: item.unread === true || item.isUnread === true,
        };
      });
  }

  /**
   * Retrieves Iranian mobile operators.
   */
  async getMobileOperators(): Promise<any[]> {
    const raw = await this.client.getMobileOperators();
    const items = extractContentArray(raw?.content, 'mobileOperators', 'operators');
    return items
      .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
      .map((item) => ({
        operatorId: String(item.operatorId || item.id || item.code || ''),
        name: String(item.name || item.operatorName || ''),
        title: normalizeOperatorName(item.title || item.name) || String(item.title || item.name || ''),
        code: item.code ? String(item.code) : undefined,
      }));
  }

  /**
   * Retrieves base top-up amounts.
   */
  async getTopUpAmounts(): Promise<any[]> {
    const raw = await this.client.getTopUpAmounts();
    const items = extractContentArray(raw?.content, 'topUpAmounts', 'amounts');
    return items
      .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
      .map((item) => {
        const amount = Number(item.amount ?? item.price ?? 0);
        return {
          amount: !isNaN(amount) ? amount : 0,
          amountFormatted: `${(!isNaN(amount) ? amount : 0).toLocaleString('en-US')} IRR`,
          operator: normalizeOperatorName(item.operator),
        };
      });
  }

  /**
   * Retrieves available PIN recharge charges.
   */
  async getAvailablePinCharges(): Promise<any[]> {
    const raw = await this.client.getAvailablePinCharges();
    const items = extractContentArray(raw?.content, 'pinCharges', 'charges', 'prices');
    return items
      .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
      .map((item) => {
        const amount = Number(item.amount ?? item.price ?? 0);
        return {
          amount: !isNaN(amount) ? amount : 0,
          amountFormatted: `${(!isNaN(amount) ? amount : 0).toLocaleString('en-US')} IRR`,
          title: item.title ? String(item.title) : undefined,
        };
      });
  }

  /**
   * Retrieves internet package catalog options.
   */
  async getPackageAvailableOptions(): Promise<any[]> {
    const raw = await this.client.getPackageAvailableOptions();
    const items = extractContentArray(raw?.content, 'packageOptions', 'options', 'packages');
    return items
      .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
      .map((item) => {
        const price = Number(item.price ?? item.amount ?? 0);
        return {
          id: item.id ? String(item.id) : undefined,
          title: String(item.title || item.name || item.packageTitle || 'بسته اینترنت'),
          price: !isNaN(price) ? price : 0,
          priceFormatted: `${(!isNaN(price) ? price : 0).toLocaleString('en-US')} IRR`,
          duration: item.duration ? String(item.duration) : undefined,
          dataLimit: item.dataLimit || item.volume ? String(item.dataLimit || item.volume) : undefined,
          operator: normalizeOperatorName(item.operator),
        };
      });
  }

  /**
   * Retrieves central interbank transfer rules and limits.
   * Normalizes PWA array/envelope response structures and parses rule descriptions.
   */
  async getInterBankRules(): Promise<any> {
    const raw = await this.client.getInterBankRules();
    const content = raw?.content;
    const rawList = Array.isArray(content)
      ? content
      : Array.isArray((content as any)?.rules)
      ? (content as any).rules
      : Array.isArray((content as any)?.interBankRules)
      ? (content as any).interBankRules
      : [];

    const rules = rawList
      .filter((r: any) => r && typeof r === 'object')
      .map((r: any) => ({
        type: String(r.interBankTransactionType || r.type || r.transferType || ''),
        description: String(r.description || r.text || '')
          .replace(/<br\s*\/?>/gi, '\n')
          .replace(/<[^>]*>/g, '')
          .replace(/&nbsp;/g, ' ')
          .trim(),
        floor: typeof r.floor === 'number' ? r.floor : typeof r.minAmount === 'number' ? r.minAmount : undefined,
        ceiling: typeof r.ceiling === 'number' ? r.ceiling : typeof r.maxAmount === 'number' ? r.maxAmount : undefined,
      }));

    const objContent = typeof content === 'object' && !Array.isArray(content) ? (content as Record<string, unknown>) : {};
    return {
      payaCeiling: typeof objContent.payaCeiling === 'number' ? objContent.payaCeiling : undefined,
      satnaFloor: typeof objContent.satnaFloor === 'number' ? objContent.satnaFloor : undefined,
      satnaCeiling: typeof objContent.satnaCeiling === 'number' ? objContent.satnaCeiling : undefined,
      cardTransferCeiling: typeof objContent.cardTransferCeiling === 'number' ? objContent.cardTransferCeiling : undefined,
      rules,
    };
  }

  /**
   * Retrieves dashboard useful services.
   */
  async getUsefulServices(): Promise<any[]> {
    const raw = await this.client.getUsefulServices();
    const items = extractContentArray(raw?.content, 'usefulServices', 'services');
    return items
      .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
      .map((item) => ({
        id: item.id ? String(item.id) : undefined,
        title: String(item.title || item.name || ''),
        link: item.link || item.url ? String(item.link || item.url) : undefined,
      }));
  }

  /**
   * Retrieves dashboard useful external links.
   */
  async getUsefulLinks(): Promise<any[]> {
    const raw = await this.client.getUsefulLinks();
    const items = extractContentArray(raw?.content, 'usefulLinks', 'links');
    return items
      .filter((item): item is Record<string, unknown> => Boolean(item && typeof item === 'object'))
      .map((item) => ({
        id: item.id ? String(item.id) : undefined,
        title: String(item.title || item.name || ''),
        url: item.url || item.link ? String(item.url || item.link) : undefined,
      }));
  }

  /**
   * Searches transactions across resources.
   */
  async searchTransactions(
    resourceType: string,
    options?: { pageSize?: number; fromDate?: string; toDate?: string; upperBound?: string }
  ): Promise<any[]> {
    const raw = await this.client.searchTransactions(resourceType, options);
    const content = (raw?.content as any) || {};
    const rawList = Array.isArray(content.transactions)
      ? content.transactions
      : Array.isArray(content.data)
      ? content.data
      : Array.isArray(content)
      ? content
      : [];
    return rawList
      .filter((item: any) => item && typeof item === 'object')
      .map((item: any) => {
        const rawAmount = Number(item.amount ?? 0);
        const absAmount = Math.abs(isNaN(rawAmount) ? 0 : rawAmount);
        const rawDate = item.date || item.transactionDate;
        const parsed = rawDate ? parseTransactionTimestamp(rawDate) : undefined;
        return {
          transactionId: String(item.transactionId || item.id || item.referenceId || ''),
          resourceType,
          date: parsed?.jalaliDate ? `${parsed.jalaliDate} ${parsed.jalaliTime || ''}`.trim() : (rawDate ? String(rawDate) : undefined),
          amount: absAmount,
          amountFormatted: `${absAmount.toLocaleString('en-US')} IRR`,
          isDebit: rawAmount < 0 || item.isDebit === true,
          description: String(item.description || item.title || ''),
        };
      });
  }

  /**
   * Retrieves available actions for Chakad digital cheque service.
   */
  async getChakadActions(): Promise<any[]> {
    const raw = await this.client.getChakadAvailableActions();
    const items = extractContentArray(raw?.content, 'availableActions', 'actions');
    return items;
  }
}

