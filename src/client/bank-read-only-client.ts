import { type AuthManager, ReauthenticationRequiredError } from '../auth/auth-manager.ts';
import type { BankAuthClient } from '../auth/bank-auth-client.ts';
import type { SessionValidator } from '../auth/session-validator.ts';
import type { KeepAliveClient, KeepAliveOutcome } from '../auth/session-refresh-manager.ts';
import type { BankApiResponse } from '../types.ts';
import { RedactingLogger } from '../logger.ts';
import {
  BankClientError,
  BankNetworkError,
  BankTimeoutError,
  BankRateLimitError,
  BankNotFoundError,
  classifyNetworkError,
} from '../reliability/network-errors.ts';

export { BankClientError, BankNetworkError, BankTimeoutError, BankRateLimitError, BankNotFoundError };

export interface TransportResponse {
  status: number;
  headers?: Record<string, string>;
  data: unknown;
}

export type TransportFn = (
  url: string,
  options: {
    method: string;
    headers: Record<string, string>;
    body?: string;
    timeoutMs: number;
  }
) => Promise<TransportResponse>;

export class BankReadOnlyClient implements KeepAliveClient {
  private logger = new RedactingLogger('BankReadOnlyClient');
  private authManager: AuthManager;
  private validator: SessionValidator;
  private baseUrl: string;
  private transport: TransportFn;
  private requestTimeoutMs: number;
  private bankAuthClient?: BankAuthClient;

  constructor(
    authManager: AuthManager,
    validator: SessionValidator,
    baseUrl: string,
    transport: TransportFn,
    requestTimeoutMs: number = 15000,
    bankAuthClient?: BankAuthClient
  ) {
    this.authManager = authManager;
    this.validator = validator;
    this.baseUrl = baseUrl;
    this.transport = transport;
    this.requestTimeoutMs = requestTimeoutMs;
    this.bankAuthClient = bankAuthClient;
  }

  setBankAuthClient(bankAuthClient: BankAuthClient): void {
    this.bankAuthClient = bankAuthClient;
  }

  /**
   * Helper that obtains a valid active token, transparently attempting auto-renewal
   * if the local idle timeout elapsed or re-authentication is flagged and credentials exist.
   */
  private async ensureToken(): Promise<string> {
    try {
      return this.authManager.getValidToken();
    } catch (err) {
      if (
        err instanceof ReauthenticationRequiredError &&
        this.bankAuthClient &&
        this.authManager.hasRenewalCredentials()
      ) {
        this.logger.info('Session requires re-authentication; attempting automated renewal with stored credentials');
        const renewed = await this.authManager.attemptAutoRenewal(this.bankAuthClient, 'local');
        if (renewed) {
          return this.authManager.getValidToken();
        }
      }
      throw err;
    }
  }

  /**
   * KeepAliveClient implementation: queries owned deposits to touch the session sliding-window.
   */
  async executeKeepAlive(token: string): Promise<KeepAliveOutcome> {
    try {
      const res = await this.rawRequest<unknown>('/en/api/deposit/ownedDeposits', 'GET', token);
      if (res && res.code === 0) {
        return { kind: 'success' };
      }
      return { kind: 'unexpected_response', message: res?.message };
    } catch (err: unknown) {
      if (err instanceof BankClientError) {
        if (err.isAuthError) {
          return {
            kind: 'auth_rejected',
            statusCode: err.statusCode,
            bankCode: err.bankCode,
            message: err.message,
          };
        }
        if (err.isRateLimited) {
          return { kind: 'rate_limited', statusCode: err.statusCode };
        }
        if (err.isNetworkError) {
          return { kind: 'network_error', error: err };
        }
        if (err.statusCode && err.statusCode >= 500) {
          return { kind: 'server_error', statusCode: err.statusCode };
        }
        return { kind: 'unexpected_response', statusCode: err.statusCode, message: err.message };
      }
      const error = err instanceof Error ? err : new Error(String(err));
      return { kind: 'network_error', error };
    }
  }

  /**
   * Retrieves owned deposits and real-time balances.
   */
  async getOwnedDeposits(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/deposit/ownedDeposits', 'GET', token);
  }

  /**
   * Directly verifies a session token against the remote bank server (/en/api/deposit/ownedDeposits).
   * Safe read-only probe that tests token validity against the bank gateway even if the
   * local daemon 5-minute idle timeout has elapsed.
   */
  async verifySession(token?: string): Promise<{ verified: boolean; message: string }> {
    const session = this.authManager.getSession();
    const targetToken = token || session?.token;
    if (!targetToken) {
      throw new BankClientError('No session token available for remote verification.', undefined, undefined, true);
    }

    const res = await this.rawRequest<unknown>('/en/api/deposit/ownedDeposits', 'GET', targetToken);
    if (res && res.code === 0) {
      return {
        verified: true,
        message: 'Session successfully verified against Bank Eghtesad Novin server.',
      };
    }
    throw new BankClientError(
      res?.message || 'Unexpected response format from bank during verification.',
      200,
      res?.code
    );
  }

  /**
   * Retrieves deposit transaction statement with pagination.
   * Path parameter is the bank's internal deposit identifier (uniqueId).
   */
  async getDepositStatement(
    depositId: string,
    params: { fromDate?: string; toDate?: string; page?: number; limit?: number }
  ): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanDeposit = encodeURIComponent(depositId.trim());
    const payload = {
      fromDate: params.fromDate?.trim() || '',
      toDate: params.toDate?.trim() || '',
      page: typeof params.page === 'number' && !isNaN(params.page) ? Math.max(0, params.page) : 0,
      limit: typeof params.limit === 'number' && !isNaN(params.limit) ? Math.max(1, Math.min(100, params.limit)) : 20,
      locationLatitude: null,
      locationLongitude: null,
    };
    return this.rawRequest<unknown>(
      `/en/api/deposit/${cleanDeposit}/statement`,
      'POST',
      token,
      JSON.stringify(payload)
    );
  }

  /**
   * Retrieves registered bank cards.
   */
  async getOwnedCards(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/card/ownedCards', 'GET', token);
  }

  /**
   * Inquires recipient cardholder name by PAN before a transfer.
   */
  async inquireCard(pan: string): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanPan = encodeURIComponent(pan.trim());
    return this.rawRequest<unknown>(`/en/api/card/inquiry?pan=${cleanPan}`, 'GET', token);
  }

  /**
   * Retrieves active client sessions.
   */
  async retrieveActiveSessions(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/user/retrieveActiveSessions', 'GET', token);
  }

  /**
   * Retrieves authenticated customer profile summary.
   */
  async getProfileSummary(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/user/profileSummary', 'GET', token);
  }

  /**
   * Retrieves saved / favorite destination bank accounts.
   */
  async getDestinationDeposits(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/deposit/destinationDeposits', 'GET', token);
  }

  /**
   * Retrieves saved / favorite destination IBANs.
   */
  async getDestinationIbans(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/iban/destinationIbans', 'GET', token);
  }

  /**
   * Retrieves saved / favorite destination cards.
   */
  async getDestinationCards(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/card/destinationCards', 'GET', token);
  }

  /**
   * Retrieves Iranian bank directory (names, codes, card BINs, logos).
   */
  async getBankList(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/baseInfo/banks', 'GET', token);
  }

  /**
   * Retrieves advertisements / banners.
   */
  async getAdvertisements(type: string = 'PopUp'): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanType = encodeURIComponent(type.trim() || 'PopUp');
    return this.rawRequest<unknown>(`/en/api/advertisement?type=${cleanType}`, 'GET', token);
  }

  /**
   * Retrieves Sayad national cheque cartable.
   */
  async getSayadCheques(params?: { limit?: number; page?: number; status?: string }): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const limit = params?.limit && params.limit > 0 ? Math.min(100, params.limit) : 20;
    const page = params?.page && params.page >= 0 ? params.page : 0;
    let path = `/en/api/sayadCheque/v2/cartable?limit=${limit}&page=${page}`;
    if (params?.status) {
      path += `&status=${encodeURIComponent(params.status.trim())}`;
    }
    return this.rawRequest<unknown>(path, 'GET', token);
  }

  /**
   * Retrieves single Sayad cheque detail by item identifier.
   */
  async getSayadChequeDetail(itemUniqueId: string): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanId = encodeURIComponent(itemUniqueId.trim());
    return this.rawRequest<unknown>(`/en/api/sayadCheque/v2/cartable/item/${cleanId}`, 'GET', token);
  }

  /**
   * Retrieves scheduled auto-transfers.
   */
  async getAutoTransfers(params: {
    type: 'NORMAL' | 'ACH';
    offset?: number;
    length?: number;
    sourceDepositNumber?: string;
  }): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const offset = params.offset && params.offset >= 0 ? params.offset : 0;
    const length = params.length && params.length > 0 ? Math.min(100, params.length) : 20;
    let path = `/en/api/autoTransfer?offset=${offset}&length=${length}&autoTransferType=${encodeURIComponent(params.type)}`;
    if (params.sourceDepositNumber) {
      path += `&sourceDepositNumber=${encodeURIComponent(params.sourceDepositNumber.trim())}`;
    }
    return this.rawRequest<unknown>(path, 'GET', token);
  }

  /**
   * Retrieves ACH (Paya/Satna) transfer reports.
   */
  async getAchTransferReport(params?: { limit?: number; page?: number }): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const limit = params?.limit && params.limit > 0 ? Math.min(100, params.limit) : 20;
    const page = params?.page && params.page >= 0 ? params.page : 0;
    return this.rawRequest<unknown>(`/en/api/ach/transfer/report?limit=${limit}&page=${page}`, 'GET', token);
  }

  /**
   * Retrieves central bank ACH reason codes.
   */
  async getAchReasons(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/ach/reasons', 'GET', token);
  }

  /**
   * Retrieves ACH transaction report by reference ID.
   */
  async getAchTransactionReport(referenceId: string): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanRef = encodeURIComponent(referenceId.trim());
    return this.rawRequest<unknown>(`/en/api/ach/transaction/report?referenceId=${cleanRef}`, 'GET', token);
  }

  /**
   * Retrieves customer loans list.
   */
  async getLoans(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/loan/', 'GET', token);
  }

  /**
   * Retrieves installments for a customer loan.
   */
  async getLoanInstallments(loanId: string): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanId = encodeURIComponent(loanId.trim());
    return this.rawRequest<unknown>(`/en/api/loan/${cleanId}/installments`, 'GET', token);
  }

  /**
   * Retrieves saved utility bills.
   */
  async getSavedBills(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/v1/bills/users', 'GET', token);
  }

  /**
   * Retrieves saved mobile top-up numbers.
   */
  async getSavedTopups(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/v1/topups/users', 'GET', token);
  }

  /**
   * Retrieves saved internet packages.
   */
  async getSavedPackages(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/v1/packages/users', 'GET', token);
  }

  /**
   * Inquires IBAN owner information.
   */
  async inquireIban(iban: string): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanIban = encodeURIComponent(iban.trim());
    return this.rawRequest<unknown>(`/en/api/iban/${cleanIban}/info`, 'GET', token);
  }

  /**
   * Converts card PAN to associated IBAN.
   */
  async convertPanToIban(pan: string): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanPan = encodeURIComponent(pan.trim());
    return this.rawRequest<unknown>(`/en/api/iban/panToIban?pan=${cleanPan}`, 'GET', token);
  }

  /**
   * Converts deposit number to IBAN.
   */
  async convertDepositToIban(depositNumber: string): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanNum = encodeURIComponent(depositNumber.trim());
    return this.rawRequest<unknown>(`/en/api/iban/depositToIban?depositNumber=${cleanNum}`, 'GET', token);
  }

  /**
   * Converts IBAN to deposit number.
   */
  async convertIbanToDeposit(iban: string): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanIban = encodeURIComponent(iban.trim());
    return this.rawRequest<unknown>(`/en/api/iban/ibanToDeposit?iban=${cleanIban}`, 'GET', token);
  }

  /**
   * Retrieves owned deposits eligible for investment funds.
   */
  async getOwnedDepositsForFund(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/deposit/ownedDepositsForFund', 'GET', token);
  }

  /**
   * Retrieves owned deposits eligible for cash cheques.
   */
  async getOwnedDepositsForCashChecks(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/deposit/ownedDepositsForCashChecks', 'GET', token);
  }

  /**
   * Retrieves authorized approvers for a shared / legal deposit.
   */
  async getDepositApprovers(depositUniqueId: string): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanId = encodeURIComponent(depositUniqueId.trim());
    return this.rawRequest<unknown>(`/en/api/deposit/${cleanId}/approvers`, 'GET', token);
  }

  /**
   * Retrieves cheque books for a deposit account.
   */
  async getChequeBooks(
    depositUniqueId: string,
    params?: { limit?: number; page?: number }
  ): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanId = encodeURIComponent(depositUniqueId.trim());
    const limit = params?.limit && params.limit > 0 ? Math.min(100, params.limit) : 20;
    const page = params?.page && params.page >= 0 ? params.page : 0;
    return this.rawRequest<unknown>(
      `/en/api/cheque/chequeBook?depositUniqueId=${cleanId}&limit=${limit}&page=${page}`,
      'GET',
      token
    );
  }

  /**
   * Retrieves individual cheque sheets within a cheque book.
   */
  async getCheckSheets(
    depositUniqueId: string,
    chequeBookNumber: string,
    isDigital: boolean = true
  ): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanId = encodeURIComponent(depositUniqueId.trim());
    const cleanBook = encodeURIComponent(chequeBookNumber.trim());
    return this.rawRequest<unknown>(
      `/en/api/cheque/v2/checkSheets?depositUniqueId=${cleanId}&chequeBookNumber=${cleanBook}&isDigital=${isDigital}`,
      'GET',
      token
    );
  }

  /**
   * Retrieves detailed cheque records for a cheque book.
   */
  async getChequeDetails(
    depositUniqueId: string,
    chequeBookNumber: string,
    params?: { limit?: number; page?: number; chequeNumber?: string; statuses?: string }
  ): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanId = encodeURIComponent(depositUniqueId.trim());
    const cleanBook = encodeURIComponent(chequeBookNumber.trim());
    const limit = params?.limit && params.limit > 0 ? Math.min(100, params.limit) : 20;
    const page = params?.page && params.page >= 0 ? params.page : 0;
    let path = `/en/api/cheque?chequeBookNumber=${cleanBook}&depositUniqueId=${cleanId}&limit=${limit}&page=${page}`;
    if (params?.chequeNumber) {
      path += `&chequeNumber=${encodeURIComponent(params.chequeNumber.trim())}`;
    }
    if (params?.statuses) {
      path += `&statuses=${encodeURIComponent(params.statuses.trim())}`;
    }
    return this.rawRequest<unknown>(path, 'GET', token);
  }

  /**
   * Queries real-time balance for an owned card.
   * Note: Bank contract specifies POST /en/api/card/ownedCards/${cardUniqueId}/balance with cardUniqueId.
   */
  async getCardBalance(cardUniqueId: string): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanId = encodeURIComponent(cardUniqueId.trim());
    return this.rawRequest<unknown>(
      `/en/api/card/ownedCards/${cleanId}/balance`,
      'POST',
      token,
      JSON.stringify({ cardUniqueId: cardUniqueId.trim() })
    );
  }

  /**
   * Queries transaction statement for an owned card.
   */
  async getCardStatement(
    cardUniqueId: string,
    payload?: Record<string, unknown>
  ): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanId = encodeURIComponent(cardUniqueId.trim());
    const body = payload ? JSON.stringify(payload) : JSON.stringify({ cardUniqueId: cardUniqueId.trim() });
    return this.rawRequest<unknown>(
      `/en/api/card/${cleanId}/statement`,
      'POST',
      token,
      body
    );
  }

  /**
   * Retrieves customer notification and email/SMS settings.
   */
  async getEmailSettings(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/user/emailSetting', 'GET', token);
  }

  /**
   * Retrieves base utility bill types (water, electricity, gas, mobile, tel, traffic).
   */
  async getBillTypes(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/baseInfo/billTypes', 'GET', token);
  }

  /**
   * Retrieves utility bill service companies directory.
   */
  async getBillCompanies(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/baseInfo/bill-companies', 'GET', token);
  }

  /**
   * Inquires a specific utility bill by type and identifier.
   */
  async inquireBill(billType: string, billId: string): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const cleanType = encodeURIComponent(billType.trim());
    const cleanId = encodeURIComponent(billId.trim());
    return this.rawRequest<unknown>(`/en/api/billInquiry/${cleanType}/${cleanId}`, 'GET', token);
  }

  /**
   * Retrieves system messages and customer notifications.
   */
  async getMessages(pageSize: number = 500): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const size = Math.min(500, Math.max(1, pageSize));
    return this.rawRequest<unknown>(`/en/api/v2/message?pageSize=${size}`, 'GET', token);
  }

  /**
   * Retrieves Iranian mobile telecommunication operators.
   */
  async getMobileOperators(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/baseInfo/mobileOperators', 'GET', token);
  }

  /**
   * Retrieves base top-up amounts available for recharge.
   */
  async getTopUpAmounts(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/v2/baseInfo/topUpAmounts', 'GET', token);
  }

  /**
   * Retrieves available PIN recharge charges.
   */
  async getAvailablePinCharges(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/baseInfo/availablePinCharges', 'GET', token);
  }

  /**
   * Retrieves available internet package catalog options.
   */
  async getPackageAvailableOptions(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/v1/package/available-options', 'GET', token);
  }

  /**
   * Retrieves central interbank transfer rules and limits (Paya / Satna).
   */
  async getInterBankRules(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/interBank/rules', 'GET', token);
  }

  /**
   * Retrieves dashboard useful services.
   */
  async getUsefulServices(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/baseInfo/useful-services', 'GET', token);
  }

  /**
   * Retrieves dashboard useful external links.
   */
  async getUsefulLinks(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/baseInfo/useful-links', 'GET', token);
  }

  /**
   * Searches transactions across resources (Card, Deposit, etc.).
   */
  async searchTransactions(
    resourceType: string,
    options?: { pageSize?: number; fromDate?: string; toDate?: string; upperBound?: string }
  ): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    const type = encodeURIComponent(resourceType.trim());
    const size = options?.pageSize && options.pageSize > 0 ? Math.min(100, options.pageSize) : 20;
    let path = `/en/api/transaction?resourceType=${type}&pageSize=${size}`;
    if (options?.fromDate) path += `&fromDateTimestamp=${encodeURIComponent(options.fromDate.trim())}`;
    if (options?.toDate) path += `&toDateTimestamp=${encodeURIComponent(options.toDate.trim())}`;
    if (options?.upperBound) path += `&upperBound=${encodeURIComponent(options.upperBound.trim())}`;
    return this.rawRequest<unknown>(path, 'GET', token);
  }

  /**
   * Retrieves available actions for Chakad digital cheque service.
   */
  async getChakadAvailableActions(): Promise<BankApiResponse<unknown>> {
    const token = await this.ensureToken();
    return this.rawRequest<unknown>('/en/api/chakad/availableActions', 'GET', token);
  }

  /**
   * Centralized HTTP dispatch pipeline with headers, timeouts, validation, and redaction.
   */
  private async rawRequest<T>(
    endpointPath: string,
    method: 'GET' | 'POST',
    token: string,
    body?: string,
    isRetry: boolean = false
  ): Promise<BankApiResponse<T>> {
    const url = `${this.baseUrl}${endpointPath}`;
    const requestGeneration = this.authManager.getSessionGeneration();

    const headers: Record<string, string> = {
      'Authorization': `bearer ${token}`,
      'X-Platform': 'PWA',
      'X-Version': '2.8.4',
      'X-BuildNo': '284',
      'Accept': 'application/json, text/plain, */*',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    };

    if (method === 'POST' || body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }

    const origin = this.baseUrl.replace(/\/+$/, '');
    headers['Origin'] = origin;
    headers['Referer'] = `${origin}/`;

    // Only attach Cookie if legitimately stored from authenticated session (no invented cookies)
    const session = this.authManager.getSession();
    if (session?.f5Cookie && session.f5Cookie.trim().length > 0) {
      headers['Cookie'] = session.f5Cookie.trim();
    }

    let response: TransportResponse;
    try {
      response = await this.transport(url, {
        method,
        headers,
        body,
        timeoutMs: this.requestTimeoutMs,
      });
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err));
      const networkOutcome = this.validator.classifyNetworkError(error);
      const classified = classifyNetworkError(error);
      this.logger.error('HTTP transport error', { endpoint: endpointPath, outcome: networkOutcome });
      if (classified.isTimeout) {
        throw new BankTimeoutError(`Bank transport timeout: ${error.message}`, this.requestTimeoutMs);
      }
      throw new BankNetworkError(
        `Bank transport failure: ${error.message}`,
        classified.code,
        classified.isTransient
      );
    }

    // Classify response
    const outcome = this.validator.classifyResponse({
      status: response.status,
      body: response.data,
    });

    if (outcome === 'AUTH_FAILED_REMOTE') {
      if (!isRetry && this.bankAuthClient && this.authManager.hasRenewalCredentials()) {
        this.logger.info('Remote bank rejected session; initiating background automatic renewal', {
          endpoint: endpointPath,
          status: response.status,
        });
        const renewed = await this.authManager.attemptAutoRenewal(this.bankAuthClient, 'remote');
        if (renewed) {
          const newToken = this.authManager.getValidToken();
          return this.rawRequest<T>(endpointPath, method, newToken, body, true);
        }
      }

      this.authManager.markRemoteAuthFailure(token, requestGeneration);
      let bankMessage = 'Bank authentication failure: session expired or token rejected.';
      let bankCode: number | undefined = undefined;
      if (response.data && typeof response.data === 'object') {
        const bodyObj = response.data as Record<string, unknown>;
        if (typeof bodyObj.code === 'number') {
          bankCode = bodyObj.code;
        }
        if (typeof bodyObj.message === 'string' && bodyObj.message.trim().length > 0) {
          bankMessage = `${bankMessage} (${bodyObj.message.trim()})`;
        }
      }
      this.logger.warn('Remote bank server rejected authentication token', {
        endpoint: endpointPath,
        status: response.status,
        bankCode,
        generation: requestGeneration,
      });
      throw new BankClientError(
        bankMessage,
        response.status,
        bankCode,
        true, // isAuthError
        false,
        false
      );
    }

    if (outcome === 'RATE_LIMITED') {
      this.logger.warn('Remote bank server indicated rate limiting (HTTP 429)');
      throw new BankClientError(
        'Bank rate limit reached. Back off before retrying.',
        response.status,
        undefined,
        false,
        false,
        true // isRateLimited
      );
    }

    if (outcome === 'CLIENT_ERROR') {
      this.logger.warn('Remote bank server returned client error', { status: response.status });
      throw new BankClientError(
        `Bank client error: HTTP ${response.status}`,
        response.status,
        undefined,
        false,
        false,
        false
      );
    }

    if (outcome === 'SERVER_ERROR' || response.status >= 500) {
      let bankMessage = `Bank server returned HTTP ${response.status}`;
      let bankCode: number | undefined = undefined;
      if (response.data && typeof response.data === 'object') {
        const bodyObj = response.data as Record<string, unknown>;
        if (typeof bodyObj.code === 'number') {
          bankCode = bodyObj.code;
        }
        if (typeof bodyObj.message === 'string' && bodyObj.message.trim().length > 0) {
          bankMessage = `${bankMessage}: ${bodyObj.message.trim()}`;
        }
      }
      this.logger.error('Remote bank server returned internal server error', {
        endpoint: endpointPath,
        method,
        status: response.status,
        bankCode,
      });
      throw new BankClientError(
        bankMessage,
        response.status,
        bankCode,
        false,
        false,
        false
      );
    }

    if (outcome === 'INVALID_RESPONSE') {
      this.logger.warn('Remote bank server returned invalid response format or status', { status: response.status });
      throw new BankClientError(
        `Invalid response format or unexpected status from bank: HTTP ${response.status}`,
        response.status,
        undefined,
        false,
        false,
        false
      );
    }

    const payload = response.data as BankApiResponse<T>;
    if (typeof payload.code === 'number' && payload.code !== 0) {
      throw new BankClientError(
        payload.message || `Bank returned error code ${payload.code}`,
        response.status,
        payload.code,
        false,
        false,
        false
      );
    }

    // Mark session as remotely verified on successful validated bank response (Fix D & L-2)
    this.authManager.markRemotelyVerified(token, requestGeneration);

    // Record successful request activity to maintain local sliding window
    this.authManager.recordActivity();

    return payload;
  }
}
