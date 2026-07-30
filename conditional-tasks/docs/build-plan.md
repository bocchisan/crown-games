# conditional-tasks — План сборки

Первый не-`DONE` этап — текущий. DoD и тесты — `docs/spec.md` + `crown-spec/docs/01-standards.md`.
Контракт игр — `games-harness.md`. Игра не заморожена (заменяется новой канистрой, старая доживает).

| Этап | Что | Статус |
|---|---|---|
| T0 | Скелет: `logic/` + `canister/`, CI, границы (zero-dep logic, нет сетей, нет таймеров) | DONE |
| T1 | `logic/` — машина `Created→Accepted/Declined→Ready→Voting→Decided` + правило вердикта + тесты | DONE¹ |
| T2 | Канистра: `register_task` (ленивая деривация), материализация на пруфе рождения, `accept`/`decline`/`ready`, текст-хеш, ~~профиль~~ | DONE²ᐟ |
| T3 | Голосование весом книги: пруф веса локально, валидность в `inspect_message`, дедуп, `V_MAX` | DONE³ |
| T4 | Вердикт: per-task резолвер, root-verdict, оплаченный pull `request_signature`, мемоизация подписи | DONE⁴ |
| T4.5 | **Путь голоса на кеш корней (`P6.6`):** `voter_weight` больше не зовёт BLS на границе | DONE⁵ |
| T5 | E2e через реальную сеть (devnet): донат → задание → голос → расчёт/возврат | DONE⁶ |
| T6 | Прод-деплой (devnet свободен; передеплой свободен) | TODO |

Ключевые DoD не-отрицательности (`cost.md §6`, тест на каждый): T3 — голос нулевого кошелька не доходит
до `update`; T4 — повтор `request_signature` на подписанной области бесплатен (подпись из хранилища,
`sign_with_schnorr` второй раз не зовётся), конкуренты оплачивают её один раз; T2 —
`register_task` без пруфа рождения не растит стабильную память.

¹ T1: `logic/` zero-dep — машина `step = advance(время) → действие` (провал действия ≡ Tick, advance персистится; overflow времени → состояние не тронуто), исчерпывающий `match` без `_`; окна из `deadline` (`cutoff = deadline − voting_period − MARGIN`, `voting_end = deadline − MARGIN`); вердикт `settle ⇔ Σdone строго > Σnot_done`, иначе Cancel (ничья/пусто/overflow весов). 18 тестов (property: settle-iff-strictly-greater; unit: границы cutoff/voting_end точны, failed-action-is-tick, decided-absorbing, дедуп/порог, overflow не двигает состояние). `clippy` strict (checked-арифметика, без unwrap/panic/indexing) чист.

² T2: канистра собрана из проверенных модулей — `protocol` (task_id+сообщения+Ed25519), `validate` (порядок отказов регистрации), `address` (PDA эскроу), `birth` (BLS-сертификат индекса против NNS root key — провалидировано PocketIC-тестом против **реального** сертификата — + свидетель рождения + пруф репутации), `resolver` (threshold-Ed25519 деривация крейтом-референсом IC; public==private тест), `request` (wire-формат+подпись), `state` (in-memory оркестрация: материализация идемпотентна, авторизация signer==recipient, ленивый tick, счётчик профиля), `config` (бейк). Эндпоинты (`init` с mainnet-trap, `bootstrap` мастер-ключа, `register_task`, `accept`/`decline`/`ready`, `set_profile`, queries; `vote`/`request_signature` — T3/T4) panic-free (let-else), собраны в wasm, `.did` сгенерирован. **56 тестов** (18 logic + 35 unit + 3 PocketIC birth-e2e), clippy/fmt/wasm чисто. Полный флоу register→голос→расчёт — на реальном devnet (T5).

ᐟ **Поправка `P7.14`** (запись, а не затирание — как на `P8` с `IC_MAINNET_ROOT_KEY`): профиля
получателя больше нет. `set_profile`, таблица `PROFILES`, счётчик, `P_MAX`, `get_profile` и гейты
`ProfileDisabled`/`GrossBelowMinimum`/`ReputationBelowMinimum` удалены; вместе с ними — пруф репутации
на пути регистрации (`birth` в этом перечне остаётся, но в `register_task` идёт **один** свидетель, а не
два). Строка выше описывает T2 таким, каким он был сдан, и потому оставлена; действующий состав —
`docs/spec.md §Методы`, обоснование — `crown-spec/docs/07-build-plan.md ¹⁷`. Счёт тестов T2 (56) с тех
пор изменился дважды: `P7.13` и `P7.14`.

³ T3: голос. `inspect_message` — **бесплатный гейт валидности** (метод==vote → подпись + target + пруф веса `reputation_from_witness(voter,recipient) ≥ MIN_VOTE_WEIGHT`; невалидный не доходит до исполнения — инв. #2). `vote` endpoint: пруф веса → `state::add_vote` (дедуп `(task_id,voter)` + порог + `Voting`-state через `step`, кэп `V_MAX=500` — инв. #7). Вес = репутация голосующего к получателю задания (пруф книги против сертифицированного корня индекса). `state::add_vote` host-тестирован (запись/дедуп/порог/V_MAX/не-Voting). **58 тестов**, clippy/fmt/wasm/.did чисто. Полный флоу голосования — на реальном devnet (T5).

⁴ T4: вердикт. `protocol::verdict_message(domain ‖ program_id(32) ‖ u8(outcome))` — байт-точно с ончейн-проверкой формы two-outcome (settle=0/cancel=1), пиннут тестом. `request_signature(chain,task)` — **оплаченный pull**: `msg_cycles_available ≥ SIGN_PRICE` → валидация → вердикт из `state::verdict` (не-`Decided` → отказ **без списания**) → `msg_cycles_accept(SIGN_PRICE)` **до** `sign_with_schnorr` → подпись резолвером `sign_with_schnorr(path=[task_id], Ed25519, verdict_message)` → `Signed{outcome,sig}`. Одна подпись области, переиспользуемая эскроу (`claim(outcome,sig)`). `sign_price` вбит в конфиг (≤ релейного). **Подпись мемоизируется** по `task_id`: попадание в
хранилище отдаётся до проверки оплаты (повтор бесплатен, как дубль вписи у индекса), право подписать
заявляется до `await` (`SignInFlight` конкуренту), `get_signature` — свободный `query`. **59 тестов**, clippy/fmt/wasm/.did чисто. Живой threshold-подпись — на devnet (T5).

⁵ T4.5: закрыто расхождение спека↔код, которое эталон нёс сам. §Методы требует «BLS сюда не идёт — она
на оплаченном `push_root`», но `voter_weight` звал `birth::certified_root`, а зовётся он из
`admit_vote` → `inspect_message`: две BLS-пары на анонимной границе **на каждый голос**. Регистрацию
расщепили на `T2`/`push_root`, путь голоса пропустили. Теперь `voter_weight` реконструирует свидетеля
веса против кеша `ROOTS` (обход хеш-дерева, newest-first), `cert` ушёл из wire-формата голоса.
`certified_root` встречается ровно один раз — в `push_root`; закреплено гейтом CI («BLS only on the
paid push_root»). **+2 теста** (`endpoint_e2e`): неоплаченный `push_root` не делает работы
(`Underpaid`), оплаченный с кривым сертификатом отбит (`BadBirthProof`, оплата не возвращается).
**63 теста** (logic 19 + канистра 31 + pocket-ic 13), clippy strict/fmt/wasm/.did чисто.

⁶ T5: живой прогон **выполнен** на Solana devnet против локального PocketIC-стека (индекс + мок SOL RPC
+ релей-прокси + tasks на `key_1`); драйвер — `e2e/t5`. Реальный `create_escrow` на 2 тест-USDC → его
настоящая транзакция дочитана до `finalized` и свёрнута индексом в **рождение** → оплаченный
`push_root` → `register_task` **прямым ingress** → `decline` → оплаченный `request_signature` →
настоящая 64-байтная Ed25519 threshold-подпись `key_1` → `claim(cancel)` на devnet: весь `gross`
вернулся донору, vault закрыт. Единственный непокрытый шов — **многопровайдерный RPC-консенсус**: SOL
RPC-канистра живёт на mainnet IC и с локальной реплики недостижима, её ответ отдаёт мок (байты
транзакции внутри — настоящие, индекс парсит и распознаёт их ровно как в проде). Закрывается только
деплоем стека на настоящий IC — это `T6`.

Прогон заодно вскрыл **устаревший артефакт**: `full_e2e` пересобирал wasm, только если файла нет, а
свой `FEE_WALLET` держал нулём — то есть тест сверялся с конфигом, из которого wasm давно не собирали.
Стоило T5 пересобрать его форсом (с настоящим `fee_wallet`), как адреса эскроу разъехались и валидный
`register_task` стал отбиваться на границе без единого читаемого слова. Теперь `full_e2e` пересобирает
всегда и берёт тот же кошелёк комиссии, что и канистра; та же правка сделана в `auction` и
`conditional-funding`. Правило общее: если байты wasm зависят от `config/`, кэш по «файл существует» —
не оптимизация, а способ тестировать не то, что задеплоишь. Сборка при этом поднята **до** создания
реплики: на холодном кэше она идёт под минуту, и простаивающая PocketIC-инстанция успевала отвалиться
по таймауту.
