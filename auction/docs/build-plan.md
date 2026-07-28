# auction — План сборки

Первый не-`DONE` этап — текущий. DoD/тесты — `docs/spec.md` + `crown-spec/docs/01-standards.md`.
Контракт игр — `games-harness.md`. Не заморожена.

| Этап | Что | Статус |
|---|---|---|
| A0 | Скелет: `logic/`+`canister/`, CI, границы (нет сетей, нет таймеров) | DONE |
| A1 | `logic/` — машина (`Bidding→Performing→Voting→Done`, `pick_winner`), подсчёт голосов (two-outcome), правило дедлайна, `resolve` per-entry + тесты | DONE¹ |
| A2 | Канистра: `create_auction` (ленивая, permissionless); `register_entry` — пруф рождения, per-entry резолвер `key([entry_id])`; `accept_lot`/`return_lot`/`return_entry`/`cancel_auction`; набор эскроу на лот | DONE² |
| A3 | **Выбор победителя получателем** (`pick_winner` из принятых лотов) + двухступенчатый борд («заявлено» вне канистры, отсечка `T`) | DONE³ |
| A4 | Голосование весом книги (валидность в `inspect_message`, дедуп, `V_MAX`); вердикт: per-entry резолвер, оплаченный pull, правило подписи | DONE⁴ |
| A5 | E2e через реальную сеть: аукцион → ставки → приём → выбор → голос → расчёт/возвраты | TODO |
| A6 | Прод-деплой | TODO |

DoD не-отрицательности (`cost.md §6`): A2 — `register_entry` без пруфа рождения не растит память,
«заявлено» вне канистры; A3 — выбор победителя, не скан/таймер; A4 — нулевой голос не доходит до `update`,
правило подписи на каждую подпись.

¹ A1: `logic/` zero-dep, форма `two-outcome`. **Машина** `Bidding→Performing{winner_lot}→Voting{started_at}→Done{winner:opt Outcome}`: время до действия; `Bidding` не имеет временного перехода (приём заморожен гейтом на `T=created_at+duration`, но состояние держится, пока получатель не `pick_winner`/`cancel`); `Performing→Done{Cancel}` при `created_at+duration+perform_window`; `Voting→Done{verdict}` при `started_at+voting_period`; overflow не двигает состояние; `Done` — поглощающее. `pick_winner(lot)` — только из `Bidding` по принятому не-возвращённому лоту → `Performing{lot}`. `return_lot` победителя в `Performing`→`Done{Cancel}`; проигравший лот в `Performing` не возвращается. **Вердикт** two-outcome (`Σdone>Σnot` строго, иначе/overflow→Cancel; property-тест). **`resolve` (per-entry)**: возвращён вклад→Cancel; возвращён лот→Cancel; иначе по состоянию×`is_winner_lot`. **Правило дедлайна** (`checked`, включительно). Канистра лоты не суммирует и не сканирует — победителя называет получатель. Общая крипта — из `crown-games-common` при A2.

² A2: канистра на `crown-games-common` (BLS-пруф/threshold-резолвер/PDA/подпись/парсинг — общие). `create_auction` — чистое эхо деривации (recipient-подписант, ноль записи): пересчитывает `auction_id` и сверяет с подписанным. `register_entry` (donor-подписант) — носитель материализации: `lot_id=sha256(auction_id‖text_hash)`, `entry_id=sha256(lot_id‖donor‖nonce)` → резолвер `key([entry_id])` → адрес эскроу → **пруф рождения** локально; первый подтверждённый вклад материализует аукцион (валидация диапазонов, `created_at` из слота), затем добавляет вклад в лот с монотонным `seq` и `entry_id`. Гейты: `gross≥min_entry`, дедлайн-правило, долив в возвращённый лот → ✗, дубль-эскроу → ✗, приём заморожен на `T`. `accept_lot`/`return_lot`/`return_entry`/`cancel_auction`/`ready`/`pick_winner` — signature-gated по `recipient`. Queries `get_auction`/`get_lot`/`get_resolver(entry_id)`.

³ A3: **выбор победителя** — `pick_winner(lot)` (recipient-подписант) над принятым не-возвращённым лотом → `Performing{winner_lot}`. Ончейн-скана «кто дороже» нет; «самый дорогой» — рекомендация борда `crown-app` (слой вне канистры), а не правило канистры. Борд «заявлено» — вне периметра; отсечка `T=created_at+duration` — граница приёма пруфов (гейт в `register_entry`). Застрявший аукцион (не выбрали/не отменили) деньги не держит — `refund()` по `deadline`.

⁴ A4: `vote` — вес = репутация голосующего к получателю (свидетель книги против корня индекса); валидность (подпись+таргет+вес≥`MIN_VOTE_WEIGHT`) отбита бесплатно в `inspect_message`; запись через машину (только `Voting`, дедуп `(lot_id,voter)`, кэп `V_MAX=500`). `request_signature(chain, auction, lot, escrow)` — **трёхступенчатое разрешение** per-entry (`resolve`) → outcome; `NoVerdict`→`NotDecided` **без списания**; иначе списание `SIGN_PRICE` **перед** `sign_with_schnorr`; подпись `key([entry_id])` над `verdict_message` (форма two-outcome), проверяется on-chain против `resolver` эскроу — один вклад, одна подпись. Реальная threshold-подпись — на A5.

**Переработка на модель «получатель выбирает» (без финал-скана/`winner.rs`/`standing`/`beats`, per-entry резолвер):** канистра слепа к суммам (`gross` валидируется при регистрации и не хранится). 38 тестов (logic 17 + канистра 21), clippy strict/fmt/wasm/.did чисто.
